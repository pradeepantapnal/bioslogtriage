"""Log ingestion utilities."""

from __future__ import annotations

from pathlib import Path


def read_log(path: str) -> str:
    """Read a UTF-8 log file and return its text."""
    return Path(path).read_text(encoding="utf-8")
