from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path
from typing import Any

import requests

from safebot.url_utils import sha256_file, virustotal_url_id

LOG = logging.getLogger(__name__)


class VirusTotalError(RuntimeError):
    pass


class RateLimiter:
    def __init__(self, max_calls: int, period_seconds: float = 60.0):
        self.max_calls = max(1, max_calls)
        self.period_seconds = period_seconds
        self.calls: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        while self.calls and now - self.calls[0] >= self.period_seconds:
            self.calls.popleft()
        if len(self.calls) >= self.max_calls:
            sleep_for = self.period_seconds - (now - self.calls[0]) + 0.05
            LOG.info("VirusTotal rate limit reached, sleeping %.1fs", sleep_for)
            time.sleep(max(0, sleep_for))
        self.calls.append(time.monotonic())


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, requests_per_minute: int = 4, timeout: float = 20.0):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.rate_limiter = RateLimiter(requests_per_minute)

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key}

    def _request(self, method: str, path_or_url: str, **kwargs: Any) -> requests.Response:
        if not self.enabled:
            raise VirusTotalError("VirusTotal API key is not configured")
        self.rate_limiter.wait()
        url = path_or_url if path_or_url.startswith("http") else f"{self.BASE_URL}{path_or_url}"
        response = self.session.request(
            method,
            url,
            headers={**self._headers(), **kwargs.pop("headers", {})},
            timeout=self.timeout,
            **kwargs,
        )
        if response.status_code == 404:
            return response
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise VirusTotalError(f"VirusTotal request failed: {response.status_code} {response.text[:300]}") from exc
        return response

    def get_url_report(self, url: str) -> dict[str, Any] | None:
        response = self._request("GET", f"/urls/{virustotal_url_id(url)}")
        if response.status_code == 404:
            return None
        return response.json()

    def scan_url(self, url: str) -> str:
        response = self._request("POST", "/urls", data={"url": url})
        return response.json()["data"]["id"]

    def get_file_report(self, file_hash: str) -> dict[str, Any] | None:
        response = self._request("GET", f"/files/{file_hash}")
        if response.status_code == 404:
            return None
        return response.json()

    def upload_file(self, path: str | Path) -> str:
        file_path = Path(path)
        with file_path.open("rb") as file:
            response = self._request("POST", "/files", files={"file": (file_path.name, file)})
        return response.json()["data"]["id"]

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        response = self._request("GET", f"/analyses/{analysis_id}")
        if response.status_code == 404:
            return None
        return response.json()

    def wait_for_analysis(self, analysis_id: str, timeout_seconds: float = 90.0, poll_seconds: float = 15.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            report = self.get_analysis(analysis_id)
            status = (report or {}).get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return report
            time.sleep(poll_seconds)
        return None


def extract_analysis_stats(report: dict[str, Any] | None) -> tuple[int, int]:
    attributes = (report or {}).get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    hits = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
    total = sum(int(value or 0) for value in stats.values()) if stats else 0
    return hits, total


def file_sha256(path: str | Path) -> str:
    return sha256_file(path)
