"""Shared score bands for ALLOW/WARN/BLOCK assessments."""

from typing import Literal

Decision = Literal["Allow", "Warn", "Block"]


def decision_for_score(score: int) -> Decision:
    """Map a trust score to its user-facing decision."""
    if score < 40:
        return "Block"
    if score <= 70:
        return "Warn"
    return "Allow"
