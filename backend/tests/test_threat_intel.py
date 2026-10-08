import sys
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import MagicMock, patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import threat_intel_service


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        threat_intel_service._feed_keys = None
        threat_intel_service._root_domains = set()
        threat_intel_service._feed_loaded_at = 0.0
        threat_intel_service._feed_checked_at = None

    @staticmethod
    def mock_feed(contents):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = contents.encode("utf-8")
        return response

    def test_feed_match_uses_no_api_key_and_checks_locally(self):
        response = self.mock_feed("https://malicious.example/login\n")
        with patch.object(threat_intel_service, "urlopen", return_value=response) as open_feed:
            result = threat_intel_service.check_urls(["https://malicious.example/login"])

        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["results"][0]["status"], "match")
        request = open_feed.call_args.args[0]
        self.assertEqual(request.full_url, threat_intel_service.DEFAULT_FEED_URL)
        self.assertFalse(request.data)

    def test_no_match_is_not_reported_as_safe(self):
        response = self.mock_feed("https://other.example/phishing\n")
        with patch.object(threat_intel_service, "urlopen", return_value=response):
            result = threat_intel_service.check_urls(["https://example.com/path"])

        self.assertEqual(result["results"][0]["status"], "no_match")
        self.assertIn("not proof", result["note"])

    def test_feed_unavailable_returns_unknown(self):
        with patch.object(threat_intel_service, "urlopen", side_effect=URLError("offline")):
            result = threat_intel_service.check_urls(["https://example.com/path"])

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["results"][0]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
