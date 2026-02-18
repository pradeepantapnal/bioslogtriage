"""Progress/postcode marker extraction."""

from __future__ import annotations

import re
from typing import TypedDict

from triage.normalize import NormalizedLine

_POSTCODE_RE = re.compile(r"\bPOSTCODE\s*=\s*<([0-9A-Fa-f]+)>")
_PROGRESS_RE = re.compile(r"\bPROGRESS\s+CODE:\s*([A-Za-z0-9]+)(?:\s+(\S+))?")


class Marker(TypedDict):
    idx: int
    kind: str
    value: str
    raw: str


def extract_markers(lines: list[NormalizedLine]) -> list[Marker]:
    """Extract deterministic progress markers from normalized lines."""
    markers: list[Marker] = []

    for line in lines:
        postcode_match = _POSTCODE_RE.search(line.text)
        if postcode_match:
            markers.append(
                {
                    "idx": line.idx,
                    "kind": "postcode",
                    "value": postcode_match.group(1).upper(),
                    "raw": line.text,
                }
            )

        progress_match = _PROGRESS_RE.search(line.text)
        if progress_match:
            progress_code = progress_match.group(1)
            suffix = progress_match.group(2)
            value = progress_code if suffix is None else f"{progress_code} {suffix}"
            markers.append(
                {
                    "idx": line.idx,
                    "kind": "progress",
                    "value": value,
                    "raw": line.text,
                }
            )

    return markers
