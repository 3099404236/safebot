from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def zh_label(self) -> str:
        return {
            RiskLevel.SAFE: "安全",
            RiskLevel.LOW: "低风险",
            RiskLevel.MEDIUM: "中风险",
            RiskLevel.HIGH: "高风险",
        }[self]

    @property
    def marker(self) -> str:
        return {
            RiskLevel.SAFE: "",
            RiskLevel.LOW: "",
            RiskLevel.MEDIUM: "🔶",
            RiskLevel.HIGH: "🔴",
        }[self]


@dataclass(frozen=True)
class ChatMessage:
    window_id: str
    group_name: str
    sender: str
    content: str
    observed_at: datetime = field(default_factory=datetime.now)
    raw_id: str | None = None
    source_control: Any | None = field(default=None, compare=False, repr=False)

    @property
    def dedupe_key(self) -> str:
        minute_bucket = self.observed_at.strftime("%Y%m%d%H%M")
        return f"{self.window_id}|{self.sender}|{self.content}|{minute_bucket}"


@dataclass(frozen=True)
class ScanFinding:
    code: str
    title: str
    detail: str
    points: int
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    target_type: str
    score: int
    level: RiskLevel
    findings: list[ScanFinding] = field(default_factory=list)
    vt_hits: int | None = None
    vt_total: int | None = None
    safe_browsing_matches: list[dict[str, Any]] = field(default_factory=list)
    suppressed: bool = False

    def important_findings(self, limit: int = 5) -> list[ScanFinding]:
        return sorted(self.findings, key=lambda item: item.points, reverse=True)[:limit]
