from __future__ import annotations

import logging
from typing import Any

import requests

LOG = logging.getLogger(__name__)


class SafeBrowsingClient:
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str, timeout: float = 10.0):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def match_urls(self, urls: list[str]) -> list[dict[str, Any]]:
        if not self.enabled or not urls:
            return []
        payload = {
            "client": {"clientId": "safebot", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": item} for item in urls],
            },
        }
        response = self.session.post(
            self.ENDPOINT,
            params={"key": self.api_key},
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json().get("matches", [])
