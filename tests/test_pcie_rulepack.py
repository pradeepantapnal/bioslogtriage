"""PCIe rulepack integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.schemas.validate import validate_output


def test_pcie_rulepack_emits_pcie_events_with_extraction(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/pcie_minimal.log")

    exit_code = cli.main(["--input", str(fixture_path), "--rulepack", "pcie"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert any(event["category"] == "pcie.enum" for event in payload["events"])
    assert any(
        "bdf" in event.get("extracted", {})
        or {"bus", "dev", "func"}.issubset(event.get("extracted", {}))
        for event in payload["events"]
    )
    assert any(
        event.get("extracted", {}).get("bdf_norm") == "0000:00:1c.0"
        for event in payload["events"]
    )
    validate_output(payload)
