"""Fault rule engine tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_fault_rulepack_emits_expected_events(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/faults_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert len(payload["events"]) >= 3
    assert any(
        event["category"] == "fault.assert" and event["severity"] == "fatal"
        for event in payload["events"]
    )
    validate_output(payload)
