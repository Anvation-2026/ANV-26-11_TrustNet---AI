"""Behavioral state and adaptive policy signals for simulated agent traces."""

from typing import Any

import database as db

WINDOW_SECONDS = 10 * 60
BLOCK_THRESHOLD = 3


def assess(role: str, tool: str, trace_id: str | None = None) -> dict[str, Any]:
    """Summarize recent same-role/tool decisions and return an explainable signal."""
    state = db.behavior_state(role, tool, WINDOW_SECONDS, trace_id)
    blocked = state["blocked"]
    trigger = blocked >= BLOCK_THRESHOLD
    score = max(0, 100 - blocked * 15 - state["warned"] * 5)
    evidence = (
        f"{state['total']} recent request(s) for {role}/{tool}: "
        f"{state['allowed']} allowed, {state['warned']} warned, {blocked} blocked in 10 minutes."
    )
    return {
        "behavioral_score": score,
        "state_analysis": state,
        "adaptive_policy": {
            "applied": trigger,
            "rule": "ADP-001" if trigger else None,
            "reason": (
                f"At least {BLOCK_THRESHOLD} blocked requests for this role and tool occurred "
                "in the last 10 minutes; otherwise-allowed requests now require review."
                if trigger else "No adaptive threshold was reached."
            ),
        },
        "evidence": evidence,
    }
