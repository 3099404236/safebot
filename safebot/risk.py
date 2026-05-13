from __future__ import annotations

from collections.abc import Iterable

from safebot.models import RiskLevel, ScanFinding, ScanResult


def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def classify_score(score: int) -> RiskLevel:
    score = clamp_score(score)
    if score <= 20:
        return RiskLevel.SAFE
    if score <= 50:
        return RiskLevel.LOW
    if score <= 80:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def result_from_findings(
    *,
    target: str,
    target_type: str,
    findings: Iterable[ScanFinding],
    vt_hits: int | None = None,
    vt_total: int | None = None,
    safe_browsing_matches: list[dict] | None = None,
    suppressed: bool = False,
) -> ScanResult:
    finding_list = list(findings)
    score = clamp_score(sum(item.points for item in finding_list))
    return ScanResult(
        target=target,
        target_type=target_type,
        score=score,
        level=classify_score(score),
        findings=finding_list,
        vt_hits=vt_hits,
        vt_total=vt_total,
        safe_browsing_matches=safe_browsing_matches or [],
        suppressed=suppressed,
    )


def virustotal_finding(hits: int, total: int, source: str = "virustotal") -> ScanFinding | None:
    if hits >= 3:
        return ScanFinding(
            code="virustotal_3plus",
            title="VirusTotal 多引擎命中",
            detail=f"VirusTotal {hits}/{total} 引擎标记恶意或可疑",
            points=60,
            source=source,
        )
    if hits >= 1:
        return ScanFinding(
            code="virustotal_1_2",
            title="VirusTotal 少量引擎命中",
            detail=f"VirusTotal {hits}/{total} 引擎标记恶意或可疑",
            points=30,
            source=source,
        )
    return None


def format_group_reply(result: ScanResult, sender: str, target_label: str) -> str:
    marker = f"{result.level.marker} " if result.level.marker else ""
    lines = [
        f"{marker}安全扫描提示（{result.level.zh_label}：{result.score}/100）",
        f"来源：{sender} 发送的{target_label}",
        "",
    ]

    findings = result.important_findings()
    if findings:
        lines.extend(f"- {item.detail}" for item in findings)
    else:
        lines.append("- 未发现明显高危信号")

    if result.vt_hits is not None and result.vt_total is not None:
        vt_line = f"- VirusTotal {result.vt_hits}/{result.vt_total} 引擎报毒或可疑"
        if all("VirusTotal" not in item.title for item in findings):
            lines.append(vt_line)

    if not result.safe_browsing_matches:
        lines.append("- Google Safe Browsing 未命中")

    suggestion = "建议：谨慎点击，注意核实是否为官方页面"
    if result.level == RiskLevel.HIGH:
        suggestion = "建议：不要打开，先联系管理员或发送者核实"
    elif result.level == RiskLevel.LOW:
        suggestion = "建议：点击前核对域名和页面来源"

    lines.extend(["", suggestion])
    return "\n".join(lines)
