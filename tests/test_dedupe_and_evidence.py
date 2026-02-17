"""Tests for evidence windows, fingerprinting, dedupe, and boot-blocking selection."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_dedupe_fingerprint_and_evidence_window(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/repeats_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path), "--context-lines", "1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    validate_output(payload)

    assert len(payload["events"]) == 1
    event = payload["events"][0]

    assert event["occurrences"] > 1
    assert event["where"]["line_range"]["start"] == 2
    assert event["where"]["other_lines"] == [5]

    evidence = event["evidence"][0]
    assert evidence["start_line"] == 1
    assert evidence["end_line"] == 3
    assert any(line["idx"] == 2 for line in evidence["lines"])

    fingerprint = event["fingerprint"]
    assert fingerprint["stable_key"]
    assert fingerprint["dedupe_group"]

    assert payload["boot_timeline"]["boot_blocking_event_id"] == event["event_id"]


def test_no_evidence_omits_evidence_lines(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/repeats_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path), "--no-evidence"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    validate_output(payload)
    evidence = payload["events"][0]["evidence"][0]
    assert "lines" not in evidence
