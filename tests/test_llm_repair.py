"""Tests for deterministic llm_synthesis repair/coercion."""

from triage.cli import _validate_llm_synthesis
from triage.llm.repair import repair_llm_synthesis


def test_repair_root_cause_string_item_validates() -> None:
    candidate = {
        "overall_confidence": 0.5,
        "executive_summary": "Potential hardware issue.",
        "root_cause_hypotheses": ["Hardware issue causing boot instability"],
        "recommended_next_actions": [],
        "missing_evidence": [],
    }

    repaired = repair_llm_synthesis(candidate, best_event_id="evt-123")

    assert isinstance(repaired["root_cause_hypotheses"][0], dict)
    assert repaired["root_cause_hypotheses"][0]["title"] == "Hardware issue causing boot instability"
    assert repaired["root_cause_hypotheses"][0]["supporting_event_ids"] == ["evt-123"]
    _validate_llm_synthesis(repaired)


def test_repair_missing_evidence_string_item_validates() -> None:
    candidate = {
        "overall_confidence": 0.5,
        "executive_summary": "Insufficient evidence.",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
        "missing_evidence": ["No evidence for PCIe training status"],
    }

    repaired = repair_llm_synthesis(candidate, best_event_id="evt-456")

    assert isinstance(repaired["missing_evidence"][0], dict)
    assert repaired["missing_evidence"][0]["priority"] == "medium"
    assert repaired["missing_evidence"][0]["supporting_event_ids"] == ["evt-456"]
    _validate_llm_synthesis(repaired)


def test_repair_adds_defaults_for_missing_keys_and_validates() -> None:
    candidate = {
        "executive_summary": "Recovered from sparse model response.",
    }

    repaired = repair_llm_synthesis(candidate, best_event_id="evt-789")

    assert repaired["overall_confidence"] == 0.2
    assert repaired["root_cause_hypotheses"] == []
    assert repaired["recommended_next_actions"] == []
    assert repaired["missing_evidence"] == []
    _validate_llm_synthesis(repaired)
