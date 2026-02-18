"""Rule evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from triage.fingerprint import stable_event_fingerprint
from triage.normalize import NormalizedLine
from triage.phases import Segment

_BDF_PATTERN = re.compile(r"^(?:(?P<domain>[0-9A-Fa-f]{4}):)?(?P<bus>[0-9A-Fa-f]{2}):(?P<dev>[0-9A-Fa-f]{2})\.(?P<func>[0-7])$")


@dataclass(frozen=True)
class Rule:
    """Compiled rule representation."""

    id: str
    category: str
    subcategory: str | None
    severity: str
    base_confidence: float
    pattern: re.Pattern[str]
    required_phase: str | None
    extracts: dict[str, str]


@dataclass(frozen=True)
class Event:
    """Event emitted by deterministic rules."""

    event_id: str
    category: str
    subcategory: str | None
    severity: str
    confidence: float
    boot_blocking: bool
    where: dict[str, Any]
    extracted: dict[str, str]
    rule_hits: list[dict[str, Any]]
    fingerprint: dict[str, str]
    occurrences: int
    evidence: list[dict[str, Any]]
    hit_text: str


def compile_rules(rulepack: dict) -> list[Rule]:
    """Compile loaded rulepack entries into regex Rules."""
    compiled: list[Rule] = []
    for raw_rule in rulepack.get("rules", []):
        compiled.append(
            Rule(
                id=raw_rule["id"],
                category=raw_rule["category"],
                subcategory=raw_rule.get("subcategory"),
                severity=raw_rule["severity"],
                base_confidence=float(raw_rule.get("base_confidence", raw_rule.get("confidence"))),
                pattern=re.compile(raw_rule["regex"]),
                required_phase=raw_rule.get("required_phase"),
                extracts={str(k): str(v) for k, v in raw_rule.get("extracts", {}).items()},
            )
        )
    return compiled


def _line_location(line_no: int, segments: list[Segment]) -> tuple[str | None, str | None]:
    for segment in segments:
        if segment.start_line <= line_no <= segment.end_line:
            phase = None
            for span in segment.phases:
                if span.start_line <= line_no <= span.end_line:
                    phase = span.phase
                    break
            return segment.segment_id, phase
    return None, None


def _event_evidence(
    lines: list[NormalizedLine],
    hit_line: int,
    segment_id: str,
    context_lines: int,
    include_lines: bool,
) -> list[dict[str, Any]]:
    start_line = max(1, hit_line - context_lines)
    end_line = min(len(lines), hit_line + context_lines)
    evidence: dict[str, Any] = {
        "ref": f"log:{segment_id}:{start_line}-{end_line}",
        "kind": "context_window",
        "start_line": start_line,
        "end_line": end_line,
    }

    if include_lines:
        evidence["lines"] = [
            {"idx": normalized_line.idx, "text": normalized_line.text}
            for normalized_line in lines[start_line - 1 : end_line]
        ]

    return [evidence]


def run_rules(
    lines: list[NormalizedLine],
    segments: list[Segment],
    rules: list[Rule],
    *,
    context_lines: int = 20,
    include_evidence_lines: bool = True,
) -> list[dict]:
    """Run single-line rules and emit de-duplicated events."""
    deduped_events: list[dict[str, Any]] = []
    stable_index: dict[str, int] = {}

    for line in lines:
        segment_id, phase = _line_location(line.idx, segments)
        resolved_segment = segment_id or "seg-unknown"
        for rule in rules:
            if rule.required_phase and phase != rule.required_phase:
                continue

            match = rule.pattern.search(line.text)
            if not match:
                continue

            confidence = rule.base_confidence
            if rule.required_phase and phase == rule.required_phase:
                confidence = min(confidence + 0.03, 0.99)
            confidence = round(confidence, 2)

            extracted = {key: value for key, value in match.groupdict().items() if value is not None}
            if rule.extracts:
                group_values = {k: v for k, v in match.groupdict().items() if v is not None}
                for key, value in rule.extracts.items():
                    if key in extracted:
                        continue
                    if value in group_values:
                        extracted[key] = group_values[value]
                    else:
                        try:
                            extracted[key] = value.format(**group_values)
                        except KeyError:
                            extracted[key] = value

            if (
                rule.category == "memory.mrc"
                and rule.subcategory == "spd_addr_zero"
                and {"mc", "ch", "dimm", "spd"}.issubset(extracted)
            ):
                extracted["spd_addr"] = f"0x{extracted['spd']}"
                extracted["slot"] = f"MC{extracted['mc']}_C{extracted['ch']}_D{extracted['dimm']}"

            if "bdf" in extracted and "bdf_norm" not in extracted:
                bdf_match = _BDF_PATTERN.match(extracted["bdf"])
                if bdf_match:
                    domain = (bdf_match.group("domain") or "0000").lower()
                    bus = bdf_match.group("bus").lower()
                    dev = bdf_match.group("dev").lower()
                    func = bdf_match.group("func")
                    extracted["bdf_norm"] = f"{domain}:{bus}:{dev}.{func}"
            where: dict[str, Any] = {
                "segment_id": resolved_segment,
                "line_range": {"start": line.idx, "end": line.idx},
            }
            if phase is not None:
                where["phase"] = phase

            event_payload: dict[str, Any] = {
                "category": rule.category,
                "subcategory": rule.subcategory,
                "severity": rule.severity,
                "extracted": extracted,
                "_normalized_hit_text": line.text,
            }
            fingerprint = stable_event_fingerprint(event_payload)

            evidence = _event_evidence(
                lines=lines,
                hit_line=line.idx,
                segment_id=resolved_segment,
                context_lines=context_lines,
                include_lines=include_evidence_lines,
            )

            if fingerprint["stable_key"] in stable_index:
                existing_event = deduped_events[stable_index[fingerprint["stable_key"]]]
                existing_event["occurrences"] += 1
                existing_event["where"].setdefault("other_lines", []).append(line.idx)
                continue

            event = Event(
                event_id=f"evt-{len(deduped_events) + 1}",
                category=rule.category,
                subcategory=rule.subcategory,
                severity=rule.severity,
                confidence=confidence,
                boot_blocking=(rule.severity == "fatal"),
                where=where,
                extracted=extracted,
                rule_hits=[
                    {
                        "rule_id": rule.id,
                        "weight": 1.0,
                        "match_confidence": confidence,
                    }
                ],
                fingerprint=fingerprint,
                occurrences=1,
                evidence=evidence,
                hit_text=line.text,
            )
            deduped_events.append(event.__dict__)
            stable_index[fingerprint["stable_key"]] = len(deduped_events) - 1

    return deduped_events
