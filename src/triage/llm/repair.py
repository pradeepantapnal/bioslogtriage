"""Deterministic repair helpers for malformed LLM synthesis payloads."""

from __future__ import annotations

def _action_from_string(text: str, best_event_id: str) -> dict:
    return {
        "action": text[:300],
        "priority": "P1",
        "expected_signal": "Observe logs/behavior change after action.",
        "supporting_event_ids": [best_event_id],
    }

def _repair_action_item(item: object, best_event_id: str) -> dict | None:
    if isinstance(item, str):
        normalized = item.strip()
        if not normalized:
            return None
        return _action_from_string(normalized, best_event_id)

    if not isinstance(item, dict):
        return None

    action = item.get("action")
    if not isinstance(action, str) or not action.strip():
        return None

    priority = item.get("priority")
    if priority not in {"P0", "P1", "P2"}:
        priority = "P1"

    expected_signal = item.get("expected_signal")
    if not isinstance(expected_signal, str) or not expected_signal.strip():
        expected_signal = "Observe logs/behavior change after action."

    supporting_event_ids = item.get("supporting_event_ids")
    if not isinstance(supporting_event_ids, list) or not supporting_event_ids:
        supporting_event_ids = [best_event_id]
    else:
        supporting_event_ids = [event_id for event_id in supporting_event_ids if isinstance(event_id, str)]
        if not supporting_event_ids:
            supporting_event_ids = [best_event_id]

    return {
        "action": action.strip()[:300],
        "priority": priority,
        "expected_signal": expected_signal.strip()[:300],
        "supporting_event_ids": supporting_event_ids,
    }

def repair_llm_synthesis(candidate: dict, best_event_id: str) -> dict:
    """Repair common llm_synthesis shape issues before validation."""

    repaired = dict(candidate)

    if "overall_confidence" not in repaired:
        repaired["overall_confidence"] = 0.2
    if "executive_summary" not in repaired:
        repaired["executive_summary"] = ""
    if "root_cause_hypotheses" not in repaired:
        repaired["root_cause_hypotheses"] = []
    if "recommended_next_actions" not in repaired:
        repaired["recommended_next_actions"] = []
    if "missing_evidence" not in repaired:
        repaired["missing_evidence"] = []

    root_cause_hypotheses = repaired.get("root_cause_hypotheses")
    if isinstance(root_cause_hypotheses, list):
        fixed_hypotheses = []
        for item in root_cause_hypotheses:
            if isinstance(item, str):
                fixed_hypotheses.append(
                    {
                        "title": item[:200],
                        "confidence": 0.3,
                        "supporting_event_ids": [best_event_id],
                        "reasoning": item,
                        "next_actions": [],
                    }
                )
                continue

            if isinstance(item, dict):
                hypothesis = dict(item)
                next_actions = hypothesis.get("next_actions")
                if isinstance(next_actions, list):
                    repaired_actions = []
                    for action in next_actions:
                        repaired_action = _repair_action_item(action, best_event_id)
                        if repaired_action is not None:
                            repaired_actions.append(repaired_action)
                    hypothesis["next_actions"] = repaired_actions
                fixed_hypotheses.append(hypothesis)
                continue

            fixed_hypotheses.append(item)

        repaired["root_cause_hypotheses"] = fixed_hypotheses

    recommended_next_actions = repaired.get("recommended_next_actions")
    if isinstance(recommended_next_actions, list):
        repaired_actions = []
        for item in recommended_next_actions:
            repaired_action = _repair_action_item(item, best_event_id)
            if repaired_action is not None:
                repaired_actions.append(repaired_action)
        repaired["recommended_next_actions"] = repaired_actions

    missing_evidence = repaired.get("missing_evidence")
    if isinstance(missing_evidence, list):
        repaired["missing_evidence"] = [
            {
                "need": item[:200],
                "why": "Model returned narrative text; structured fields missing.",
                "how": "Collect targeted logs/telemetry; rerun triage.",
                "priority": "medium",
                "supporting_event_ids": [best_event_id],
            }
            if isinstance(item, str)
            else item
            for item in missing_evidence
        ]

    return repaired
