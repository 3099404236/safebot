from __future__ import annotations

import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from safebot.models import ScanFinding
from safebot.settings import RuleSettings
from safebot.url_utils import get_domain

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    whois = None

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover - optional dependency
    BeautifulSoup = None

LOG = logging.getLogger(__name__)

JS_PATTERNS = [
    "document.cookie",
    "eval(",
    "atob(",
    "keydown",
    "keypress",
]


class UrlRuleScanner:
    def __init__(self, settings: RuleSettings):
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "safebot/0.1 (+https://local.invalid/security-scan)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def scan(self, url: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._check_domain_age(url))
        findings.extend(self._check_tls(url))
        findings.extend(self._check_page_content(url))
        return findings

    def _check_domain_age(self, url: str) -> list[ScanFinding]:
        if whois is None:
            LOG.debug("python-whois is unavailable; skipping domain age check")
            return []
        domain = get_domain(url)
        if not domain:
            return []
        try:
            data = whois.whois(domain)
            created = data.creation_date
            if isinstance(created, list):
                created = min(item for item in created if item)
            if not created:
                return []
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
        except Exception as exc:
            LOG.debug("WHOIS lookup failed for %s: %s", domain, exc)
            return []

        if age_days < self.settings.new_domain_days:
            return [
                ScanFinding(
                    code="new_domain",
                    title="新注册域名",
                    detail=f"域名注册仅 {age_days} 天",
                    points=15,
                    source="rules",
                    metadata={"domain": domain, "age_days": age_days},
                )
            ]
        return []

    def _check_tls(self, url: str) -> list[ScanFinding]:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return [
                ScanFinding(
                    code="no_https",
                    title="未使用 HTTPS",
                    detail="链接未使用 HTTPS 加密",
                    points=10,
                    source="rules",
                )
            ]
        hostname = parsed.hostname
        if not hostname:
            return []
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.settings.request_timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    pass
        except Exception as exc:
            return [
                ScanFinding(
                    code="invalid_tls",
                    title="HTTPS 证书异常",
                    detail=f"HTTPS 证书校验失败：{exc.__class__.__name__}",
                    points=10,
                    source="rules",
                    metadata={"host": hostname},
                )
            ]
        return []

    def _check_page_content(self, url: str) -> list[ScanFinding]:
        if BeautifulSoup is None:
            LOG.debug("BeautifulSoup is unavailable; skipping HTML content rules")
            return []
        try:
            response = self.session.get(url, timeout=self.settings.request_timeout_seconds, stream=True, allow_redirects=True)
            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower():
                return []
            content = _read_capped(response, self.settings.max_html_bytes)
            html = content.decode(response.encoding or "utf-8", errors="ignore")
        except Exception as exc:
            LOG.debug("Failed to fetch page content for %s: %s", url, exc)
            return []

        soup = BeautifulSoup(html, "html.parser")
        text_blob = soup.get_text(" ", strip=True).lower()
        findings: list[ScanFinding] = []

        if self._has_brand_password_form(soup, text_blob):
            findings.append(
                ScanFinding(
                    code="phishing_login_form",
                    title="疑似仿冒登录表单",
                    detail="页面包含密码输入框和品牌/学校关键词，疑似仿冒登录",
                    points=40,
                    source="rules",
                )
            )

        hidden_iframes = _hidden_iframe_count(soup)
        if hidden_iframes:
            findings.append(
                ScanFinding(
                    code="hidden_iframe",
                    title="隐藏 iframe",
                    detail=f"页面包含 {hidden_iframes} 个隐藏 iframe",
                    points=20,
                    source="rules",
                    metadata={"count": hidden_iframes},
                )
            )

        js_hits = _js_keyword_hits(html)
        if js_hits:
            findings.append(
                ScanFinding(
                    code="suspicious_js",
                    title="可疑 JavaScript 行为",
                    detail="页面脚本包含高危关键词：" + "、".join(js_hits[:5]),
                    points=20,
                    source="rules",
                    metadata={"keywords": js_hits},
                )
            )

        if _has_meta_refresh(soup):
            findings.append(
                ScanFinding(
                    code="meta_refresh",
                    title="可疑跳转",
                    detail="页面包含 meta refresh 跳转",
                    points=20,
                    source="rules",
                )
            )

        return findings

    def _has_brand_password_form(self, soup: object, text_blob: str) -> bool:
        has_password = bool(soup.select('input[type="password"]'))
        if not has_password:
            return False
        keyword_blob = text_blob + " " + " ".join(str(item.get("name", "")) for item in soup.select("input"))
        return any(keyword.lower() in keyword_blob for keyword in self.settings.brand_keywords)


def _read_capped(response: requests.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    return b"".join(chunks)[:max_bytes]


def _hidden_iframe_count(soup: object) -> int:
    count = 0
    for iframe in soup.select("iframe"):
        style = (iframe.get("style") or "").replace(" ", "").lower()
        width = str(iframe.get("width") or "").strip()
        height = str(iframe.get("height") or "").strip()
        if "display:none" in style or "visibility:hidden" in style or width == "0" or height == "0":
            count += 1
    return count


def _js_keyword_hits(html: str) -> list[str]:
    lowered = html.lower()
    hits = [pattern for pattern in JS_PATTERNS if pattern.lower() in lowered]
    if re.search(r"addEventListener\s*\(\s*['\"](?:keydown|keypress)", html, flags=re.IGNORECASE):
        hits.append("key event listener")
    return list(dict.fromkeys(hits))


def _has_meta_refresh(soup: object) -> bool:
    for meta in soup.select("meta[http-equiv]"):
        if str(meta.get("http-equiv", "")).lower() == "refresh":
            return True
    return False
