"""Log normalization utilities."""

from __future__ import annotations

from dataclasses import dataclass
import re

_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F]")
_WEIRD_WHITESPACE_RE = re.compile(r"[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]+")


@dataclass(frozen=True)
class NormalizedLine:
    """A single log line with raw and normalized representations."""

    idx: int
    raw: str
    text: str


def _normalize_line(raw_line: str) -> str:
    """Normalize a single line of log text."""
    text = raw_line.rstrip("\r\n")
    text = text.replace("\x00", "")
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_RE.sub("", text)
    text = _WEIRD_WHITESPACE_RE.sub(" ", text)
    return text.strip()


def load_and_normalize(path: str) -> list[NormalizedLine]:
    """Load log file and return normalized lines."""
    normalized: list[NormalizedLine] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            normalized.append(
                NormalizedLine(
                    idx=idx,
                    raw=raw_line,
                    text=_normalize_line(raw_line),
                )
            )
    return normalized


def normalization_stats(lines: list[NormalizedLine]) -> dict[str, int]:
    """Compute normalization metrics for normalized lines."""
    empty_line_count = sum(1 for line in lines if line.text == "")
    return {
        "line_count": len(lines),
        "empty_line_count": empty_line_count,
    }
