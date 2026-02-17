"""LLM synthesis schema and fallback behavior tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_llm_synthesis_valid_response_passes(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    valid_synthesis = {
        "overall_confidence": 0.72,
        "executive_summary": "Observed a boot-blocking memory-related fault.",
        "root_cause_hypotheses": [
            {
                "title": "Memory initialization failure",
                "confidence": 0.72,
                "supporting_event_ids": ["evt-1"],
                "reasoning": "The selected event indicates a memory init error during early boot.",
                "next_actions": [
                    {
                        "action": "Capture full MRC training logs",
                        "priority": "P1",
                        "expected_signal": "Additional memory training error signatures",
                        "supporting_event_ids": ["evt-1"],
                    }
                ],
            }
        ],
        "recommended_next_actions": [
            {
                "action": "Re-run boot with verbose memory diagnostics",
                "priority": "P1",
                "expected_signal": "Consistent reproduction and richer fault context",
                "supporting_event_ids": ["evt-1"],
            }
        ],
    }

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: valid_synthesis,
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_synthesis"] == valid_synthesis
    validate_output(data)


def test_llm_synthesis_invalid_response_uses_fallback(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    invalid_synthesis = {
        "executive_summary": "Missing required fields and no citations",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
    }

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: invalid_synthesis,
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_synthesis"]["overall_confidence"] == 0.0
    assert data["llm_synthesis"]["executive_summary"] == "LLM synthesis failed; see errors."
    assert data["llm_synthesis"]["root_cause_hypotheses"] == []
    assert data["llm_synthesis"]["recommended_next_actions"] == []
    assert data["llm_synthesis"]["missing_evidence"] == []
    assert data["llm_synthesis"]["errors"]
    validate_output(data)
