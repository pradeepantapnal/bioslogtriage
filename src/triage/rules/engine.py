"""Rule evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from triage.normalize import NormalizedLine
from triage.phases import Segment


@dataclass(frozen=True)
class Rule:
    """Compiled rule representation."""

    id: str
    category: str
    severity: str
    base_confidence: float
    pattern: re.Pattern[str]
    required_phase: str | None


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


def compile_rules(rulepack: dict) -> list[Rule]:
    """Compile loaded rulepack entries into regex Rules."""
    compiled: list[Rule] = []
    for raw_rule in rulepack.get("rules", []):
        compiled.append(
            Rule(
                id=raw_rule["id"],
                category=raw_rule["category"],
                severity=raw_rule["severity"],
                base_confidence=float(raw_rule["confidence"]),
                pattern=re.compile(raw_rule["regex"]),
                required_phase=raw_rule.get("required_phase"),
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


def run_rules(lines: list[NormalizedLine], segments: list[Segment], rules: list[Rule]) -> list[dict]:
    """Run single-line rules and emit events."""
    events: list[dict] = []

    for line in lines:
        segment_id, phase = _line_location(line.idx, segments)
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
            where: dict[str, Any] = {
                "segment_id": segment_id or "seg-unknown",
                "line_range": {"start": line.idx, "end": line.idx},
            }
            if phase is not None:
                where["phase"] = phase

            event = Event(
                event_id=f"evt-{len(events) + 1}",
                category=rule.category,
                subcategory=None,
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
            )
            events.append(event.__dict__)

    return events
