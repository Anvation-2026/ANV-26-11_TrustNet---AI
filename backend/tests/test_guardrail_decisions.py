import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
_test_db_dir = tempfile.TemporaryDirectory(prefix="pygenic-tests-")
os.environ["PYGENIC_DB_PATH"] = str(Path(_test_db_dir.name) / "test.db")

import main
from decision_policy import decision_for_score


class ScoreBandTests(unittest.TestCase):
    def test_score_boundaries(self):
        self.assertEqual(decision_for_score(39), "Block")
        self.assertEqual(decision_for_score(40), "Warn")
        self.assertEqual(decision_for_score(70), "Warn")
        self.assertEqual(decision_for_score(71), "Allow")

    def test_guardrail_hard_blocks_remain_blocks(self):
        cases = [
            (main.AgentRequest(role="Viewer", tool="delete_user", action="Execute",
                               params={"user_id": 42, "reason": "Test"}), "Unauthorized Action"),
            (main.AgentRequest(role="Admin", tool="process_payment", action="Execute",
                               params={"recipient": "Test", "amount": -1, "currency": "USD"}), "Invalid Parameter"),
            (main.AgentRequest(role="Admin", tool="process_payment", action="Execute",
                               params={"recipient": "Test", "amount": 100001, "currency": "USD"}), "Policy Violation"),
        ]
        for request, expected_risk in cases:
            with self.subTest(risk=expected_risk):
                with patch.object(main.behavior_engine, "assess", return_value={
                    "behavioral_score": 10,
                    "state_analysis": {"total": 0, "allowed": 0, "warned": 0, "blocked": 0},
                    "adaptive_policy": {"applied": False, "reason": "No adaptive threshold was reached."},
                    "evidence": "isolated test trace",
                }):
                    result = main.evaluate(request)
                self.assertEqual(result["decision"], "Block")
                self.assertEqual(result["risk_type"], expected_risk)

    def test_redundant_call_is_warning(self):
        request = main.AgentRequest(role="Viewer", tool="read_file", action="Read",
                                   params={"path": "/documents/policy.pdf"})
        with patch.object(main.db, "is_duplicate", return_value=True):
            self.assertEqual(main.decide(request)[0], "Warn")

    def test_adaptive_demo_sequence_is_repeatable_and_session_scoped(self):
        trace_id = "isolated-adaptive-test"
        for _ in range(3):
            result = main.evaluate(main.AgentRequest(
                role="Viewer", tool="read_file", action="Read", params={"path": ""}, trace_id=trace_id))
            self.assertEqual(result["decision"], "Block")
        result = main.evaluate(main.AgentRequest(
            role="Viewer", tool="read_file", action="Read",
            params={"path": "/documents/company_policy.pdf"}, trace_id=trace_id))
        self.assertEqual(result["decision"], "Warn")
        self.assertEqual(result["rule"], "ADP-001")
        self.assertEqual(result["state_analysis"]["blocked"], 3)
        self.assertEqual(main.db.behavior_state("Viewer", "read_file", 600, "another-session")["total"], 0)


if __name__ == "__main__":
    unittest.main()
