"""Evidence pack construction for bounded LLM prompts."""

from __future__ import annotations

import copy
import json
from typing import Any

_SEVERITY_SCORES = {"fatal": 100, "high": 60, "medium": 30, "low": 10, "info": 1}



def _event_rank_score(event: dict[str, Any]) -> int:
    explicit = event.get("score")
    if isinstance(explicit, (int, float)):
        score = int(explicit)
    else:
        severity = str(event.get("severity", "")).lower()
        confidence = float(event.get("confidence", 0.0))
        score = _SEVERITY_SCORES.get(severity, 0) + round(confidence * 20)

    if event.get("boot_blocking"):
        score += 1000
    return score


def rank_events(events: list[dict]) -> list[dict]:
    """Rank events descending by importance for LLM evidence selection."""
    return sorted(
        events,
        key=lambda event: (
            _event_rank_score(event),
            -int(event.get("where", {}).get("line_range", {}).get("start", 10**9)),
        ),
        reverse=True,
    )



def _timeline_summary(output: dict[str, Any]) -> dict[str, Any]:
    timeline = output.get("boot_timeline")
    if not isinstance(timeline, dict):
        return {"segments": [], "boot_blocking_event_id": None}

    summarized_segments: list[dict[str, Any]] = []
    for segment in timeline.get("segments", []):
        if not isinstance(segment, dict):
            continue

        phases = []
        for phase in segment.get("phases", []):
            if not isinstance(phase, dict):
                continue
            phases.append(
                {
                    "phase": phase.get("phase"),
                    "start_line": phase.get("start_line"),
                    "end_line": phase.get("end_line"),
                }
            )

        summarized_segments.append(
            {
                "segment_id": segment.get("segment_id"),
                "start_line": segment.get("start_line"),
                "end_line": segment.get("end_line"),
                "phases": phases,
            }
        )

    return {
        "segments": summarized_segments,
        "boot_blocking_event_id": timeline.get("boot_blocking_event_id"),
    }



def _trimmed_event(event: dict[str, Any]) -> dict[str, Any]:
    keep_fields = (
        "event_id",
        "category",
        "subcategory",
        "severity",
        "confidence",
        "boot_blocking",
        "where",
        "fingerprint",
        "extracted",
        "rule_hits",
        "evidence",
        "hit_text",
    )
    trimmed = {field: copy.deepcopy(event[field]) for field in keep_fields if field in event}

    evidence = trimmed.get("evidence")
    if isinstance(evidence, list):
        cleaned: list[dict[str, Any]] = []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            kept = {
                "ref": item.get("ref"),
                "kind": item.get("kind"),
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
            }
            if "lines" in item:
                kept["lines"] = copy.deepcopy(item.get("lines"))
            cleaned.append(kept)
        trimmed["evidence"] = cleaned

    return trimmed



def _serialized_size_chars(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))



def _ensure_hit_line_evidence(event: dict[str, Any]) -> bool:
    """Ensure event evidence contains at least one line entry for the hit line."""
    where = event.get("where") if isinstance(event.get("where"), dict) else {}
    line_start = where.get("line_range", {}).get("start") if isinstance(where.get("line_range"), dict) else None
    if not isinstance(line_start, int):
        return False

    hit_text = event.get("hit_text")
    if not isinstance(hit_text, str):
        hit_text = ""

    evidence = event.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        event["evidence"] = evidence

    if not evidence or not isinstance(evidence[0], dict):
        evidence.insert(
            0,
            {
                "ref": f"log:{where.get('segment_id', 'seg-unknown')}:{line_start}-{line_start}",
                "kind": "context_window",
                "start_line": line_start,
                "end_line": line_start,
            },
        )

    first = evidence[0]
    lines = first.get("lines")
    hit_line = {"idx": line_start, "text": hit_text}
    if not isinstance(lines, list) or not lines:
        first["lines"] = [hit_line]
        return True

    matched = next((line for line in lines if isinstance(line, dict) and line.get("idx") == line_start), None)
    if matched is None:
        first["lines"] = [hit_line]
        return True

    text_value = matched.get("text") if isinstance(matched.get("text"), str) else hit_text
    first["lines"] = [{"idx": line_start, "text": text_value}]
    return True


def build_evidence_pack(output: dict, top_k: int = 8, max_chars: int = 30000) -> dict:
    """Build a budget-bounded evidence pack suitable for LLM prompting."""
    events = output.get("events") if isinstance(output.get("events"), list) else []
    ranked = rank_events(events)

    selected_events = [_trimmed_event(event) for event in ranked[: max(0, top_k)]]
    if events and not selected_events:
        selected_events = [_trimmed_event(ranked[0])]

    evidence_pack: dict[str, Any] = {
        "schema_version": output.get("schema_version"),
        "boot_timeline": _timeline_summary(output),
        "selected_events": selected_events,
    }

    trimming_applied: list[str] = []
    final_chars = _serialized_size_chars(evidence_pack)

    for idx, event in enumerate(selected_events):
        if _ensure_hit_line_evidence(event):
            trimming_applied.append(f"ensured_hit_line:event_index={idx}")
    final_chars = _serialized_size_chars(evidence_pack)

    while final_chars > max_chars and len(selected_events) > 1:
        selected_events.pop()
        trimming_applied.append("dropped_low_ranked_event")
        final_chars = _serialized_size_chars(evidence_pack)

    evidence_pack["evidence_pack_meta"] = {
        "top_k_requested": top_k,
        "events_included": len(selected_events),
        "max_chars": max_chars,
        "trimming_applied": trimming_applied[:12],
        "trimming_count": len(trimming_applied),
    }

    while _serialized_size_chars(evidence_pack) > max_chars and len(selected_events) > 1:
        selected_events.pop()
        trimming_applied.append("dropped_low_ranked_event")
        evidence_pack["evidence_pack_meta"]["events_included"] = len(selected_events)
        evidence_pack["evidence_pack_meta"]["trimming_applied"] = trimming_applied[:12]
        evidence_pack["evidence_pack_meta"]["trimming_count"] = len(trimming_applied)

    evidence_pack["evidence_pack_meta"]["final_chars"] = _serialized_size_chars(evidence_pack)
    if evidence_pack["evidence_pack_meta"]["final_chars"] > max_chars:
        evidence_pack["evidence_pack_meta"]["trimming_applied"] = ["meta_compacted"]
        evidence_pack["evidence_pack_meta"]["final_chars"] = _serialized_size_chars(evidence_pack)

    return evidence_pack
