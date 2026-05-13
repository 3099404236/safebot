import unittest

from safebot.models import RiskLevel, ScanFinding
from safebot.risk import classify_score, result_from_findings, virustotal_finding


class RiskTest(unittest.TestCase):
    def test_classify_score_boundaries(self):
        self.assertEqual(classify_score(20), RiskLevel.SAFE)
        self.assertEqual(classify_score(21), RiskLevel.LOW)
        self.assertEqual(classify_score(51), RiskLevel.MEDIUM)
        self.assertEqual(classify_score(81), RiskLevel.HIGH)

    def test_result_score_is_capped(self):
        findings = [
            ScanFinding("a", "A", "a", 80, "test"),
            ScanFinding("b", "B", "b", 80, "test"),
        ]
        result = result_from_findings(target="x", target_type="url", findings=findings)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.level, RiskLevel.HIGH)

    def test_virustotal_finding_thresholds(self):
        self.assertIsNone(virustotal_finding(0, 70))
        self.assertEqual(virustotal_finding(1, 70).points, 30)
        self.assertEqual(virustotal_finding(3, 70).points, 60)


if __name__ == "__main__":
    unittest.main()
