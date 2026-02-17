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
        "missing_evidence": [],
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


def test_llm_synthesis_invalid_response_is_repaired(monkeypatch, capsys) -> None:
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
    assert data["llm_synthesis"]["overall_confidence"] == 0.2
    assert data["llm_synthesis"]["executive_summary"] == invalid_synthesis["executive_summary"]
    assert data["llm_synthesis"]["root_cause_hypotheses"] == []
    assert data["llm_synthesis"]["recommended_next_actions"] == []
    assert data["llm_synthesis"]["missing_evidence"] == []
    assert "errors" not in data["llm_synthesis"]
    validate_output(data)




def test_llm_synthesis_echoed_input_uses_fallback(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: {"evidence_pack": {"selected_events": []}},
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_synthesis"]["errors"]
    assert "echoed input" in data["llm_synthesis"]["errors"][0]["detail"]
    validate_output(data)


def test_llm_synthesis_unwraps_nested_object(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    wrapped_synthesis = {
        "llm_synthesis": {
            "overall_confidence": 0.68,
            "executive_summary": "Memory training failure likely blocks boot.",
            "root_cause_hypotheses": [
                {
                    "title": "Memory training instability",
                    "confidence": 0.68,
                    "supporting_event_ids": ["evt-1"],
                    "reasoning": "Observed MRC-related error suggests failed training sequence.",
                    "next_actions": [
                        {
                            "action": "Collect memory training trace",
                            "priority": "P1",
                            "expected_signal": "Detailed training step failure code",
                            "supporting_event_ids": ["evt-1"],
                        }
                    ],
                }
            ],
            "recommended_next_actions": [
                {
                    "action": "Retest with known-good DIMM",
                    "priority": "P1",
                    "expected_signal": "Boot succeeds or error signature changes",
                    "supporting_event_ids": ["evt-1"],
                }
            ],
            "missing_evidence": [],
        }
    }

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: wrapped_synthesis,
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["llm_synthesis"] == wrapped_synthesis["llm_synthesis"]
    validate_output(data)



def test_llm_synthesis_repairs_missing_evidence_strings(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    malformed_synthesis = {
        "overall_confidence": 0.61,
        "executive_summary": "Likely memory training issue.",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
        "missing_evidence": ["Need DIMM SPD dump"],
    }

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        lambda self, system, user, schema: malformed_synthesis,
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    repaired = data["llm_synthesis"]["missing_evidence"][0]
    assert repaired["need"] == "Need DIMM SPD dump"
    assert repaired["priority"] == "medium"
    assert repaired["supporting_event_ids"]
    validate_output(data)

def test_llm_synthesis_generation_exception_uses_fallback(monkeypatch, capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    def _raise_generate_json(self, system, user, schema):
        raise ValueError("simulated generation failure")

    monkeypatch.setattr(
        "triage.llm.ollama_client.OllamaClient.generate_json",
        _raise_generate_json,
    )

    exit_code = cli.main(["--input", str(fixture_path), "--llm"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert data["llm_synthesis"]["overall_confidence"] == 0.0
    assert data["llm_synthesis"]["errors"]
    assert data["llm_synthesis"]["errors"][0]["type"] == "ValueError"
    assert data["llm_synthesis"]["errors"][0]["message"] == "Failed to generate or validate LLM synthesis"
    validate_output(data)
