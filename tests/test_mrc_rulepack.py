"""MRC rulepack integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_mrc_rulepack_emits_memory_events_and_boot_blocking(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/mrc_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path), "--rulepack", "mrc"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert any(event["category"] == "memory.mrc" for event in payload["events"])
    assert any(event["severity"] == "fatal" for event in payload["events"])
    assert payload["boot_timeline"]["boot_blocking_event_id"] is not None
    validate_output(payload)
