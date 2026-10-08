import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import analysis_service


class ContentAnalysisTests(unittest.TestCase):
    def test_clean_and_flagged_messages_follow_score_bands(self):
        clean = analysis_service.analyze("sender@example.com", "Report", "The report is attached.")
        flagged = analysis_service.analyze("sender@example.com", "Notice", "Urgent: please review this update.")
        self.assertEqual(clean["decision"], "Allow")
        self.assertEqual(flagged["trust_score"], 70)
        self.assertEqual(flagged["decision"], "Warn")

    def test_live_threat_match_blocks_with_provider_evidence(self):
        provider_result = {
            "provider": "Phishing.Database", "status": "checked", "checked_at": "2026-01-01T00:00:00+00:00",
            "results": [{"url": "https://example.com/login", "status": "match", "threat_types": ["SOCIAL_ENGINEERING"]}],
            "note": "No known threat-list match is not proof that a URL is safe.",
        }
        with patch.object(analysis_service.threat_intel_service, "check_urls", return_value=provider_result):
            result = analysis_service.analyze("sender@example.com", "Notice",
                                              "Review https://example.com/login", check_urls=True)
        self.assertEqual(result["decision"], "Block")
        self.assertEqual(result["threat_intelligence"][0]["status"], "match")
        self.assertIn("Threat intelligence match", result["findings"])


if __name__ == "__main__":
    unittest.main()
