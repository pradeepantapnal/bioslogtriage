"""Log normalization utilities."""

from __future__ import annotations


def normalize_log(text: str) -> str:
    """Normalize line endings and trim trailing whitespace-only lines."""
    normalized_lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]

    while normalized_lines and normalized_lines[-1] == "":
        normalized_lines.pop()

    return "\n".join(normalized_lines)
