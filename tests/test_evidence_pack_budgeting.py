"""Tests for evidence pack budgeting and CLI LLM input wiring."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.llm.evidence_pack import build_evidence_pack


def _make_event(event_id: str, severity: str, confidence: float, lines_count: int, *, boot_blocking: bool = False) -> dict:
    return {
        "event_id": event_id,
        "category": "fault",
        "subcategory": "synthetic",
        "severity": severity,
        "confidence": confidence,
        "boot_blocking": boot_blocking,
        "where": {
            "segment_id": "seg_0",
            "phase": "DXE",
            "line_range": {"start": 10, "end": 11},
        },
        "fingerprint": {"stable_key": f"stable-{event_id}", "dedupe_group": f"dg-{event_id}"},
        "extracted": {"msg": "synthetic"},
        "rule_hits": [{"rule_id": "r1", "weight": 1.0, "match_confidence": 1.0}],
        "evidence": [
            {
                "ref": "log://fixture",
                "kind": "window",
                "start_line": 1,
                "end_line": lines_count,
                "lines": [{"idx": idx + 1, "text": "X" * 250} for idx in range(lines_count)],
            }
        ],
    }


def test_build_evidence_pack_enforces_budget_and_keeps_top_event() -> None:
    output = {
        "schema_version": "0.1.0",
        "events": [
            _make_event("evt-fatal", "fatal", 0.9, 30, boot_blocking=True),
            _make_event("evt-high-1", "high", 0.9, 30),
            _make_event("evt-high-2", "high", 0.8, 30),
            _make_event("evt-low", "low", 0.5, 30),
        ],
        "boot_timeline": {
            "segments": [
                {
                    "segment_id": "seg_0",
                    "start_line": 1,
                    "end_line": 100,
                    "phases": [{"phase": "DXE", "start_line": 10, "end_line": 90, "confidence": 0.9}],
                }
            ],
            "boot_blocking_event_id": "evt-fatal",
        },
    }

    pack = build_evidence_pack(output, top_k=4, max_chars=3500)

    assert pack["evidence_pack_meta"]["trimming_applied"]
    assert pack["evidence_pack_meta"]["final_chars"] <= 3500
    assert any(event["event_id"] == "evt-fatal" for event in pack["selected_events"])


def test_cli_llm_sends_evidence_pack_only(monkeypatch, capsys) -> None:
    captured: dict[str, str] = {}

    def _fake_generate_json(self, system: str, user: str, schema: dict) -> dict:
        captured["system"] = system
        captured["user"] = user
        captured["schema"] = json.dumps(schema)
        return {"ok": True}

    monkeypatch.setattr("triage.llm.ollama_client.OllamaClient.generate_json", _fake_generate_json)

    fixture_path = Path("fixtures/synthetic_logs/faults_minimal.log")
    exit_code = cli.main(["--input", str(fixture_path), "--llm", "--llm-top-k", "2", "--llm-max-chars", "5000"])

    out = capsys.readouterr().out
    payload = json.loads(captured["user"])
    parsed = json.loads(out)

    assert exit_code == 0
    assert "selected_events" in payload
    assert "events" not in payload
    assert "You must only use facts from the provided evidence_pack JSON" in captured["system"]
    assert parsed["llm_input"]["evidence_pack_meta"]["max_chars"] == 5000
