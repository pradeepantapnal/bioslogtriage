"""Event enrichment for watchdog/boot-blocking deterministic anchors."""

from __future__ import annotations

import re
from typing import Iterable

from triage.normalize import NormalizedLine
from triage.signals.progress import Marker

_WATCHDOG_RE = re.compile(r"watchdog", re.IGNORECASE)
_SUBSYSTEM_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("memory", ("MRC", "DDR", "DIMM", "SPD")),
    ("pcie", ("PCIE",)),
    ("nvme", ("NVME",)),
    ("sata", ("SATA", "AHCI")),
    ("spi", ("SPI",)),
    ("usb", ("USB",)),
]


def _event_is_watchdog(event: dict) -> bool:
    category = str(event.get("category", ""))
    subcategory = str(event.get("subcategory", ""))
    rule_hits = event.get("rule_hits")
    rule_ids = []
    if isinstance(rule_hits, list):
        rule_ids = [str(rule_hit.get("rule_id", "")) for rule_hit in rule_hits if isinstance(rule_hit, dict)]
    return bool(
        _WATCHDOG_RE.search(category)
        or _WATCHDOG_RE.search(subcategory)
        or any("WATCHDOG" in rule_id.upper() for rule_id in rule_ids)
    )


def _find_preceding_marker(markers: list[Marker], line_no: int, window: int = 2000) -> Marker | None:
    candidates = [marker for marker in markers if marker["idx"] <= line_no and (line_no - marker["idx"]) <= window]
    if not candidates:
        return None
    return max(candidates, key=lambda marker: marker["idx"])


def _scan_text_for_subsystem(chunks: Iterable[str]) -> str | None:
    text = "\n".join(chunk for chunk in chunks if chunk)
    if not text:
        return None

    upper = text.upper()
    for subsystem, tokens in _SUBSYSTEM_KEYWORDS:
        if any(token in upper for token in tokens):
            return subsystem
    return None


def _event_context_text(event: dict, lines: list[NormalizedLine], line_no: int) -> list[str]:
    context: list[str] = []
    hit_text = event.get("hit_text")
    if isinstance(hit_text, str):
        context.append(hit_text)

    evidence = event.get("evidence")
    if isinstance(evidence, list) and evidence:
        first = evidence[0] if isinstance(evidence[0], dict) else None
        if isinstance(first, dict):
            evidence_lines = first.get("lines")
            if isinstance(evidence_lines, list):
                for line in evidence_lines:
                    if isinstance(line, dict) and isinstance(line.get("text"), str):
                        context.append(line["text"])

    start = max(1, line_no - 5)
    end = min(len(lines), line_no + 5)
    for normalized in lines[start - 1 : end]:
        context.append(normalized.text)

    return context


def enrich_events(
    events: list[dict],
    markers: list[Marker],
    lines: list[NormalizedLine],
    boot_blocking_event_id: str | None = None,
) -> None:
    """Enrich watchdog-like and boot-blocking events with deterministic extracted anchors."""
    for event in events:
        is_target = _event_is_watchdog(event) or (
            isinstance(boot_blocking_event_id, str) and event.get("event_id") == boot_blocking_event_id
        )
        if not is_target:
            continue

        where = event.get("where") if isinstance(event.get("where"), dict) else {}
        line_range = where.get("line_range") if isinstance(where.get("line_range"), dict) else {}
        line_no = line_range.get("start")
        if not isinstance(line_no, int):
            continue

        extracted = event.get("extracted")
        if not isinstance(extracted, dict):
            extracted = {}
            event["extracted"] = extracted

        marker = _find_preceding_marker(markers, line_no)
        if marker is not None:
            if marker["kind"] == "progress":
                extracted["last_progress_code"] = marker["value"]
            if marker["kind"] == "postcode":
                extracted["postcode_hex"] = marker["value"]
            extracted["last_milestone_line"] = marker["idx"]

        subsystem = _scan_text_for_subsystem(_event_context_text(event, lines, line_no))
        if subsystem:
            extracted["suspected_subsystem"] = subsystem
