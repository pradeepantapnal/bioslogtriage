"""Deterministic repair helpers for malformed LLM synthesis payloads."""

from __future__ import annotations


def repair_llm_synthesis(candidate: dict, best_event_id: str) -> dict:
    """Repair common llm_synthesis type mismatches conservatively.

    Currently repairs:
    - missing_evidence: list[str] -> list[object]
    - recommended_next_actions: list[str] -> list[object]
    """

    repaired = dict(candidate)

    missing_evidence = repaired.get("missing_evidence")
    if isinstance(missing_evidence, list) and any(isinstance(item, str) for item in missing_evidence):
        repaired["missing_evidence"] = [
            {
                "need": item,
                "why": "Model returned narrative text instead of structured object.",
                "how": "Re-run with stricter template; optionally increase model size.",
                "priority": "medium",
                "supporting_event_ids": [best_event_id],
            }
            if isinstance(item, str)
            else item
            for item in missing_evidence
        ]

    recommended_next_actions = repaired.get("recommended_next_actions")
    if isinstance(recommended_next_actions, list) and any(
        isinstance(item, str) for item in recommended_next_actions
    ):
        repaired["recommended_next_actions"] = [
            {
                "action": item,
                "priority": "P1",
                "expected_signal": "",
                "supporting_event_ids": [best_event_id],
            }
            if isinstance(item, str)
            else item
            for item in recommended_next_actions
        ]

    return repaired
