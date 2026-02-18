"""Deterministic signal extraction helpers."""

from triage.signals.progress import extract_markers
from triage.signals.stalls import detect_stalls

__all__ = ["extract_markers", "detect_stalls"]
