"""Deterministic signal extraction tests for progress/stall/watchdog triage."""

from __future__ import annotations

import json
from pathlib import Path

from triage import cli
from triage.signals.stalls import detect_stalls


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
    assert isinstance(stalls, list)

    watchdog_events = [
        event
        for event in payload["events"]
        if "watchdog" in event["category"].lower() or "watchdog" in str(event.get("subcategory", "")).lower()
    ]
    assert watchdog_events

    extracted = watchdog_events[0]["extracted"]
    assert extracted.get("suspected_subsystem") == "spi"
    assert extracted.get("last_progress_code") or extracted.get("postcode_hex")


def test_detect_stalls_with_lower_gap_threshold() -> None:
    stalls = detect_stalls(
        [
            {"idx": 10, "kind": "progress", "value": "AA", "raw": "PROGRESS CODE: AA"},
            {"idx": 30, "kind": "postcode", "value": "0000AA10", "raw": "POSTCODE = <0000AA10>"},
        ],
        [],
        gap_lines=10,
    )

    assert stalls
    assert stalls[0]["gap_lines"] == 20


def test_watchdog_enrichment_includes_progress_or_postcode_and_subsystem(capsys) -> None:
    fixture_path = Path("fixtures/synthetic_logs/final_watchdog_case.log")

    exit_code = cli.main(["--input", str(fixture_path), "--output-mode", "slim"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0

    segment = payload["boot_timeline"]["segments"][0]
    assert "last_good_milestone" in segment

    assert "signals" in payload
    assert "stalls" in payload["signals"]

    boot_blocking_id = payload["boot_timeline"]["boot_blocking_event_id"]

    target_events = [
        event
        for event in payload["events"]
        if event["event_id"] == boot_blocking_id
        or any("WATCHDOG" in hit.get("rule_id", "") for hit in event.get("rule_hits", []))
    ]
    assert target_events

    extracted = target_events[0]["extracted"]
    assert extracted.get("last_progress_code") or extracted.get("postcode_hex")
    assert extracted.get("suspected_subsystem") == "memory"
