"""Tests for deterministic llm_synthesis repair/coercion."""

from triage.cli import _validate_llm_facts, _validate_llm_synthesis
from triage.llm.repair import repair_llm_synthesis
from triage.llm.repair_facts import repair_llm_facts

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

def test_repair_llm_facts_drops_empty_fact_items_and_validates() -> None:
    candidate = {
        "overall_grounding_confidence": 0.5,
        "facts": [
            {
                "fact": "",
                "supporting_event_ids": ["evt-1"],
                "confidence": 0.5,
            }
        ],
    }

    repaired = repair_llm_facts(candidate)

    assert repaired["facts"] == []
    _validate_llm_facts(repaired)

def test_repair_recommended_actions_complete_required_fields_and_validate() -> None:
    candidate = {
        "overall_confidence": 0.5,
        "executive_summary": "Action details are sparse.",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [{"action": "Do X"}],
        "missing_evidence": [],
    }

    repaired = repair_llm_synthesis(candidate, best_event_id="evt-123")

    assert repaired["recommended_next_actions"] == [
        {
            "action": "Do X",
            "priority": "P1",
            "expected_signal": "Observe logs/behavior change after action.",
            "supporting_event_ids": ["evt-123"],
        }
    ]
    _validate_llm_synthesis(repaired)
