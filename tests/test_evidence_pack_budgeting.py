"""Tests for evidence pack budgeting and CLI LLM input wiring."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.llm.evidence_pack import build_evidence_pack


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: object | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {"response": '{"ok": true}'}
        self.text = text

    def json(self) -> object:
        return self._payload


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


def test_cli_llm_sends_budgeted_prompt_and_timeout(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def _fake_post(url: str, payload: dict, timeout_s: int, model: str) -> _FakeResponse:
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout_s"] = timeout_s
        captured["model"] = model
        return _FakeResponse()

    monkeypatch.setattr("triage.llm.ollama_client._post", _fake_post)

    fixture_path = Path("fixtures/synthetic_logs/faults_minimal.log")
    exit_code = cli.main(
        [
            "--input",
            str(fixture_path),
            "--llm",
            "--llm-top-k",
            "2",
            "--llm-max-chars",
            "5000",
            "--llm-timeout-s",
            "321",
        ]
    )

    out = capsys.readouterr().out
    parsed = json.loads(out)
    payload = captured["payload"]

    assert exit_code == 0
    assert isinstance(payload, dict)
    assert len(str(payload["prompt"])) <= 5000
    assert captured["timeout_s"] == 321
    assert "selected_events" in json.loads(payload["prompt"])
    assert "events" not in json.loads(payload["prompt"])
    assert parsed["llm_input"]["evidence_pack_meta"]["max_chars"] == 5000


def test_cli_dump_llm_prompt_writes_file(monkeypatch, tmp_path) -> None:
    dump_path = tmp_path / "prompt.json"

    def _fake_post(url: str, payload: dict, timeout_s: int, model: str) -> _FakeResponse:
        return _FakeResponse()

    monkeypatch.setattr("triage.llm.ollama_client._post", _fake_post)

    fixture_path = Path("fixtures/synthetic_logs/faults_minimal.log")
    exit_code = cli.main(
        [
            "--input",
            str(fixture_path),
            "--llm",
            "--llm-max-chars",
            "1400",
            "--dump-llm-prompt",
            str(dump_path),
        ]
    )

    assert exit_code == 0
    assert dump_path.exists()
    assert len(dump_path.read_text(encoding="utf-8")) <= 1400
