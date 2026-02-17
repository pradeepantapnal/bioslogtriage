"""Boot phase detection utilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from triage.normalize import NormalizedLine


class Phase(str, Enum):
    """Known boot phases."""

    SEC = "SEC"
    PEI = "PEI"
    DXE = "DXE"
    BDS = "BDS"


@dataclass(frozen=True)
class PhaseSpan:
    """A contiguous line span for a boot phase."""

    phase: str
    start_line: int
    end_line: int
    confidence: float


@dataclass(frozen=True)
class Segment:
    """A top-level boot segment containing phase spans."""

    segment_id: str
    start_line: int
    end_line: int
    phases: list[PhaseSpan]


_MARKERS: dict[Phase, list[tuple[re.Pattern[str], bool]]] = {
    Phase.SEC: [
        (re.compile(r"\bSecCore\b", re.IGNORECASE), True),
        (re.compile(r"\bSEC\b.{0,30}\b(Entry|Start|Phase)\b", re.IGNORECASE), False),
        (re.compile(r"\b(Entry|Start|Phase)\b.{0,30}\bSEC\b", re.IGNORECASE), False),
    ],
    Phase.PEI: [
        (re.compile(r"\bPeiCore\b", re.IGNORECASE), True),
        (re.compile(r"\bPEI\b", re.IGNORECASE), False),
    ],
    Phase.DXE: [
        (re.compile(r"\bDxeCore\b", re.IGNORECASE), True),
        (re.compile(r"\bDXE\b", re.IGNORECASE), False),
    ],
    Phase.BDS: [
        (re.compile(r"\bBdsDxe\b", re.IGNORECASE), True),
        (re.compile(r"\bBoot\s+Device\s+Selection\b", re.IGNORECASE), False),
        (re.compile(r"\bBDS\b", re.IGNORECASE), False),
    ],
}

_PHASE_ORDER = [Phase.SEC, Phase.PEI, Phase.DXE, Phase.BDS]


def _line_hits_phase(text: str, phase: Phase) -> tuple[bool, bool, int]:
    """Return marker match metadata for a line and phase.

    Returns (matched, has_strong_match, total_matches).
    """
    match_count = 0
    strong = False
    for marker_re, is_strong in _MARKERS[phase]:
        if marker_re.search(text):
            match_count += 1
            strong = strong or is_strong
    return (match_count > 0, strong, match_count)


def detect_phases(lines: list[NormalizedLine]) -> list[PhaseSpan]:
    """Detect boot phase spans from normalized lines."""
    phase_hits: dict[Phase, dict[str, int | bool]] = {}

    for line in lines:
        for phase in _PHASE_ORDER:
            matched, strong, matches = _line_hits_phase(line.text, phase)
            if not matched:
                continue

            if phase not in phase_hits:
                phase_hits[phase] = {
                    "start_line": line.idx,
                    "strong": strong,
                    "matches": matches,
                }
            else:
                phase_hits[phase]["strong"] = bool(phase_hits[phase]["strong"]) or strong
                phase_hits[phase]["matches"] = int(phase_hits[phase]["matches"]) + matches
            break

    if not phase_hits:
        return []

    ordered = sorted(phase_hits.items(), key=lambda item: int(item[1]["start_line"]))

    spans: list[PhaseSpan] = []
    max_line = lines[-1].idx if lines else 0
    for pos, (phase, data) in enumerate(ordered):
        start_line = int(data["start_line"])
        strong = bool(data["strong"])
        matches = int(data["matches"])

        if pos + 1 < len(ordered):
            end_line = int(ordered[pos + 1][1]["start_line"]) - 1
        else:
            end_line = max_line

        base_confidence = 0.95 if strong else 0.80
        confidence = min(base_confidence + max(0, matches - 1) * 0.03, 0.99)

        spans.append(
            PhaseSpan(
                phase=phase.value,
                start_line=start_line,
                end_line=end_line,
                confidence=round(confidence, 2),
            )
        )

    return spans


def build_segments(lines: list[NormalizedLine], phases: list[PhaseSpan]) -> list[Segment]:
    """Build basic boot segments.

    Current deterministic behavior: emit a single segment spanning entire file.
    """
    if not lines:
        return []

    return [
        Segment(
            segment_id="seg-1",
            start_line=lines[0].idx,
            end_line=lines[-1].idx,
            phases=phases,
        )
    ]
