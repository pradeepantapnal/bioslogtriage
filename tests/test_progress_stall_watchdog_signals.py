"""Deterministic signal extraction tests for progress/stall/watchdog triage."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli


def test_progress_stall_watchdog_signals_present(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/progress_stall_watchdog.log")

    exit_code = cli.main(["--input", str(fixture_path)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0

    segment = payload["boot_timeline"]["segments"][0]
    assert segment["last_good_milestone"]["kind"] == "postcode"
    assert segment["last_good_milestone"]["value"] == "0000DB03"

    stalls = payload["signals"]["stalls"]
    assert stalls
    assert stalls[0]["gap_lines"] > 5000

    watchdog_events = [
        event
        for event in payload["events"]
        if "watchdog" in event["category"].lower() or "watchdog" in str(event.get("subcategory", "")).lower()
    ]
    assert watchdog_events

    extracted = watchdog_events[0]["extracted"]
    assert extracted.get("suspected_subsystem") == "spi"
    assert extracted.get("last_progress_code") or extracted.get("postcode_hex")
