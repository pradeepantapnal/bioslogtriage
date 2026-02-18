"""Two-pass LLM pipeline tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_llm_two_pass_valid_facts_and_synthesis(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    valid_facts = {
        "overall_grounding_confidence": 0.81,
        "facts": [
            {
                "fact": f"Fact {idx}",
                "supporting_event_ids": ["evt-1"],
                "confidence": 0.7,
            }
            for idx in range(1, 6)
        ],
    }
    valid_synthesis = {
        "overall_confidence": 0.66,
        "executive_summary": "Memory init fault appears boot-blocking.",
        "root_cause_hypotheses": [
            {
                "title": "Memory init failure",
                "confidence": 0.66,
                "supporting_event_ids": ["evt-1"],
                "reasoning": "Facts indicate repeat memory initialization errors.",
                "next_actions": [
                    {
                        "action": "Collect training details",
                        "priority": "P1",
                        "expected_signal": "Specific memory training step failure code",
                        "supporting_event_ids": ["evt-1"],
                    }
                ],
            }
        ],
        "recommended_next_actions": [
            {
                "action": "Retest with known-good DIMM",
                "priority": "P1",
                "expected_signal": "Boot behavior changes",
                "supporting_event_ids": ["evt-1"],
            }
        ],
        "missing_evidence": [],
    }

    calls = iter([valid_facts, valid_synthesis])

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: next(calls),
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_facts"] == valid_facts
    assert data["llm_synthesis"] == valid_synthesis
    validate_output(data)


def test_llm_two_pass_invalid_facts_falls_back_and_continues(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    invalid_facts = {
        "overall_grounding_confidence": 0.5,
        "facts": [{"fact": "too few and missing fields"}],
    }
    invalid_synthesis = {
        "executive_summary": "Incomplete",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
    }

    calls = iter([invalid_facts, invalid_synthesis])

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: next(calls),
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_facts"]["overall_grounding_confidence"] == 0.0
    assert data["llm_facts"]["facts"] == []
    assert data["llm_facts"]["errors"]
    assert data["llm_synthesis"]["overall_confidence"] == 0.2
    validate_output(data)
