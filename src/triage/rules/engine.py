"""Rule evaluation engine."""

from __future__ import annotations


def summarize_log(text: str) -> dict[str, int]:
    """Return a lightweight summary of a log text."""
    lines = [line for line in text.splitlines() if line.strip()]
    return {
        "line_count": len(lines),
        "error_count": sum(1 for line in lines if "error" in line.lower()),
        "warning_count": sum(1 for line in lines if "warn" in line.lower()),
    }
