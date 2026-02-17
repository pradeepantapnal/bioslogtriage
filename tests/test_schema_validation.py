"""Schema validation tests for CLI output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage import cli
from triage.schemas.validate import validate_output


def test_cli_output_validates_against_schema(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/minimal_boot.log")

    exit_code = cli.main(["--input", str(fixture_path)])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    validate_output(data)


def test_validate_output_raises_when_required_field_missing() -> None:
    data = {
        "schema_version": "0.0.0",
        "normalization": {"line_count": 1},
        "events": [],
        "llm_enabled": False,
    }
    del data["schema_version"]

    with pytest.raises(ValueError, match="schema_version"):
        validate_output(data)


def test_validate_output_accepts_trimming_count_in_evidence_pack_meta() -> None:
    data = {
        "schema_version": "0.0.0",
        "normalization": {"line_count": 1},
        "events": [],
        "llm_enabled": True,
        "llm_input": {
            "boot_timeline": {"segments": [], "boot_blocking_event_id": None},
            "selected_events": [],
            "evidence_pack_meta": {
                "top_k_requested": 5,
                "events_included": 0,
                "max_chars": 5000,
                "final_chars": 250,
                "trimming_applied": [],
                "trimming_count": 0,
            },
        },
    }

    validate_output(data)
