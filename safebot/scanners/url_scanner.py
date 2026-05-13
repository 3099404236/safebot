from __future__ import annotations

import logging

from safebot.models import ScanFinding, ScanResult
from safebot.risk import result_from_findings, virustotal_finding
from safebot.scanners.safebrowsing import SafeBrowsingClient
from safebot.scanners.url_rules import UrlRuleScanner
from safebot.scanners.virustotal import VirusTotalClient, extract_analysis_stats
from safebot.whitelist import Whitelist

LOG = logging.getLogger(__name__)


class UrlScanner:
    def __init__(
        self,
        *,
        virustotal: VirusTotalClient | None,
        safe_browsing: SafeBrowsingClient | None,
        rules: UrlRuleScanner,
        whitelist: Whitelist,
        submit_to_virustotal: bool = False,
    ):
        self.virustotal = virustotal
        self.safe_browsing = safe_browsing
        self.rules = rules
        self.whitelist = whitelist
        self.submit_to_virustotal = submit_to_virustotal

    def scan(self, url: str) -> ScanResult:
        whitelisted = self.whitelist.contains_url(url)
        findings: list[ScanFinding] = []
        vt_hits: int | None = None
        vt_total: int | None = None
        matches: list[dict] = []

        if self.virustotal and self.virustotal.enabled:
            try:
                report = self.virustotal.get_url_report(url)
                if report is None and self.submit_to_virustotal:
                    analysis_id = self.virustotal.scan_url(url)
                    report = self.virustotal.wait_for_analysis(analysis_id)
                vt_hits, vt_total = extract_analysis_stats(report)
                vt = virustotal_finding(vt_hits, vt_total)
                if vt:
                    findings.append(vt)
            except Exception as exc:
                LOG.warning("VirusTotal URL scan failed for %s: %s", url, exc)

        if not whitelisted and self.safe_browsing and self.safe_browsing.enabled:
            try:
                matches = self.safe_browsing.match_urls([url])
                if matches:
                    findings.append(
                        ScanFinding(
                            code="safe_browsing_hit",
                            title="Google Safe Browsing 命中",
                            detail="Google Safe Browsing 黑名单命中",
                            points=80,
                            source="safe_browsing",
                            metadata={"matches": matches},
                        )
                    )
            except Exception as exc:
                LOG.warning("Safe Browsing scan failed for %s: %s", url, exc)

        if not whitelisted:
            findings.extend(self.rules.scan(url))

        return result_from_findings(
            target=url,
            target_type="url",
            findings=findings,
            vt_hits=vt_hits,
            vt_total=vt_total,
            safe_browsing_matches=matches,
            suppressed=whitelisted,
        )
