"""Output shaping utilities for triage CLI JSON payloads."""

from __future__ import annotations

from copy import deepcopy


_OUTPUT_MODES = {"full", "slim", "tiny"}


def _extract_evidence_records(output: dict) -> list[dict]:
    records: list[dict] = []
    events = output.get("events")
    if not isinstance(events, list):
        return records

    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = event.get("event_id")
        evidence_entries = event.get("evidence")
        if not isinstance(evidence_entries, list):
            continue

        for evidence in evidence_entries:
            if not isinstance(evidence, dict):
                continue
            record = {
                "event_id": event_id,
                "ref": evidence.get("ref"),
                "start_line": evidence.get("start_line"),
                "end_line": evidence.get("end_line"),
                "lines": evidence.get("lines") if isinstance(evidence.get("lines"), list) else [],
            }
            records.append(record)

    return records


def apply_output_mode(output: dict, mode: str) -> tuple[dict, list[dict]]:
    """Apply output mode transforms and return (main_output, evidence_records)."""
    if mode not in _OUTPUT_MODES:
        raise ValueError(f"Unsupported output mode: {mode}")

    transformed = deepcopy(output)
    if mode == "full":
        return transformed, []

    evidence_records = _extract_evidence_records(output)
    events = transformed.get("events")
    if not isinstance(events, list):
        return transformed, evidence_records

    for event in events:
        if not isinstance(event, dict):
            continue

        hit_line = event.get("where", {}).get("line_range", {}).get("start")
        evidence_entries = event.get("evidence")
        if not isinstance(evidence_entries, list):
            continue

        for evidence in evidence_entries:
            if not isinstance(evidence, dict):
                continue

            if mode == "tiny":
                evidence.pop("lines", None)
                continue

            lines = evidence.get("lines")
            if not isinstance(lines, list):
                evidence.pop("lines", None)
                continue

            if isinstance(hit_line, int):
                matched_line = next(
                    (line for line in lines if isinstance(line, dict) and line.get("idx") == hit_line),
                    None,
                )
            else:
                matched_line = None

            if matched_line is None:
                evidence["lines"] = []
            else:
                evidence["lines"] = [matched_line]

    return transformed, evidence_records


def extract_evidence_records(output: dict) -> list[dict]:
    """Public helper to write evidence artifact files without reshaping output."""
    return _extract_evidence_records(output)
