"""Storage rulepack integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_storage_rulepack_emits_nvme_and_sata_events(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/storage_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path), "--rulepack", "storage"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert any(event["category"] == "storage.nvme" for event in payload["events"])
    assert any(event["category"] == "storage.sata" for event in payload["events"])
    assert any(event["severity"] in {"high", "fatal"} for event in payload["events"])
    validate_output(payload)
