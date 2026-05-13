from __future__ import annotations

import json
from pathlib import Path

from safebot.url_utils import get_domain, is_domain_or_subdomain


class Whitelist:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.domains: set[str] = set()
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.domains = set()
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.domains = {item.lower().strip(".") for item in raw.get("domains", []) if item}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"domains": sorted(self.domains)}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def add(self, domain: str) -> str:
        normalized = get_domain(domain) or domain.lower().strip(".")
        self.domains.add(normalized)
        self.save()
        return normalized

    def remove(self, domain: str) -> str:
        normalized = get_domain(domain) or domain.lower().strip(".")
        self.domains.discard(normalized)
        self.save()
        return normalized

    def contains_url(self, url: str) -> bool:
        hostname = get_domain(url)
        return any(is_domain_or_subdomain(hostname, item) for item in self.domains)

    def list_domains(self) -> list[str]:
        return sorted(self.domains)
