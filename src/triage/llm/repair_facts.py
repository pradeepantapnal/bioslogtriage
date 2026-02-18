"""Deterministic repair helpers for malformed LLM facts payloads."""

from __future__ import annotations


def _clamp(value: object, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number < 0:
        return 0.0
    if number > 1:
        return 1.0
    return number


def repair_llm_facts(candidate: dict) -> dict:
    """Repair common llm_facts shape issues before validation."""

    repaired = dict(candidate) if isinstance(candidate, dict) else {}

    repaired["overall_grounding_confidence"] = _clamp(
        repaired.get("overall_grounding_confidence"),
        default=0.2,
    )

    facts = repaired.get("facts")
    if not isinstance(facts, list):
        facts = []

    fixed_facts: list[dict] = []
    for item in facts:
        if not isinstance(item, dict):
            continue

        fact_text = item.get("fact")
        if not isinstance(fact_text, str) or not fact_text.strip():
            continue

        supporting_event_ids = item.get("supporting_event_ids")
        if not isinstance(supporting_event_ids, list) or len(supporting_event_ids) < 1:
            continue

        cleaned_event_ids = [event_id for event_id in supporting_event_ids if isinstance(event_id, str)]
        if not cleaned_event_ids:
            continue

        fixed_facts.append(
            {
                "fact": fact_text,
                "supporting_event_ids": cleaned_event_ids,
                "confidence": _clamp(item.get("confidence"), default=0.3),
            }
        )

    repaired["facts"] = fixed_facts
    return repaired
