"""Tests for deterministic boot phase detection."""

from __future__ import annotations

from pathlib import Path

from triage.normalize import load_and_normalize
from triage.phases import detect_phases


def test_detect_phases_returns_ordered_spans() -> None:
    fixture_path = Path("fixtures/synthetic_logs/phases_minimal.log")

    lines = load_and_normalize(str(fixture_path))
    spans = detect_phases(lines)

    assert [span.phase for span in spans] == ["SEC", "PEI", "DXE", "BDS"]


def test_detect_phases_start_end_lines_and_confidence() -> None:
    fixture_path = Path("fixtures/synthetic_logs/phases_minimal.log")

    lines = load_and_normalize(str(fixture_path))
    spans = detect_phases(lines)

    assert spans[0].start_line == 2
    assert spans[0].end_line == 4
    assert spans[1].start_line == 5
    assert spans[1].end_line == 7
    assert spans[2].start_line == 8
    assert spans[2].end_line == 10
    assert spans[3].start_line == 11
    assert spans[3].end_line == 14

    assert all(span.confidence >= 0.8 for span in spans)
