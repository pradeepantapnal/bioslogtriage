"""Stall detection based on large marker gaps."""

from __future__ import annotations

from typing import TypedDict

from triage.phases import PhaseSpan
from triage.signals.progress import Marker


class LastMilestone(TypedDict):
    kind: str
    line: int
    value: str


class StallSignal(TypedDict):
    phase: str
    start_line: int
    end_line: int
    gap_lines: int
    last_milestone: LastMilestone
    confidence: float


def _phase_for_line(line_no: int, phases: list[PhaseSpan]) -> str:
    for phase in phases:
        if phase.start_line <= line_no <= phase.end_line:
            return phase.phase
    return "unknown"


def detect_stalls(
    markers: list[Marker],
    phases: list[PhaseSpan],
    gap_lines: int = 5000,
) -> list[StallSignal]:
    """Detect possible stalls by finding unusually large gaps between markers."""
    if len(markers) < 2:
        return []

    ordered_markers = sorted(markers, key=lambda marker: marker["idx"])
    stalls: list[StallSignal] = []

    for prev, current in zip(ordered_markers, ordered_markers[1:]):
        phase = _phase_for_line(prev["idx"], phases)
        if phase != _phase_for_line(current["idx"], phases):
            continue

        gap = current["idx"] - prev["idx"]
        if gap <= gap_lines:
            continue

        stalls.append(
            {
                "phase": phase,
                "start_line": prev["idx"],
                "end_line": current["idx"],
                "gap_lines": gap,
                "last_milestone": {
                    "kind": prev["kind"],
                    "line": prev["idx"],
                    "value": prev["value"],
                },
                "confidence": 0.6,
            }
        )

    return stalls
