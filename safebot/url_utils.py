from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse


URL_RE = re.compile(
    r"(?P<url>(?:https?://|www\.)[^\s<>'\"，。！？；（）【】]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text or ""):
        url = match.group("url").rstrip(").,;:!?，。；：！？")
        if url.lower().startswith("www."):
            url = f"https://{url}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def get_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower().strip(".")


def registrable_domain(hostname: str) -> str:
    parts = hostname.lower().strip(".").split(".")
    if len(parts) <= 2:
        return hostname.lower().strip(".")
    common_second_level = {"com", "net", "org", "edu", "gov", "co"}
    if len(parts) >= 3 and parts[-2] in common_second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_domain_or_subdomain(hostname: str, trusted_domain: str) -> bool:
    hostname = hostname.lower().strip(".")
    trusted_domain = trusted_domain.lower().strip(".")
    return hostname == trusted_domain or hostname.endswith(f".{trusted_domain}")


def virustotal_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
