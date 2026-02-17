"""Output mode shaping tests."""

from __future__ import annotations

from triage.output import apply_output_mode
from triage.schemas.validate import validate_output


def _sample_output() -> dict:
    return {
        "schema_version": "0.1.0",
        "normalization": {"line_count": 300},
        "llm_enabled": False,
        "events": [
            {
                "event_id": "evt-1",
                "category": "memory",
                "severity": "high",
                "confidence": 0.93,
                "boot_blocking": True,
                "fingerprint": {"stable_key": "memory-init-fail", "dedupe_group": "memory"},
                "where": {
                    "phase": "PEI",
                    "segment_id": "seg-1",
                    "line_range": {"start": 101, "end": 101},
                },
                "extracted": {},
                "rule_hits": [{"rule_id": "memory.fail", "weight": 1.0, "match_confidence": 0.9}],
                "evidence": [
                    {
                        "ref": "log:seg-1:100-120",
                        "kind": "window",
                        "start_line": 100,
                        "end_line": 120,
                        "lines": [
                            {"idx": 100, "text": "pre context"},
                            {"idx": 101, "text": "ERROR memory init failed"},
                            {"idx": 102, "text": "post context"},
                        ],
                    }
                ],
            }
        ],
        "boot_timeline": {"segments": [], "boot_outcome": "unknown", "boot_blocking_event_id": "evt-1"},
    }


def test_apply_output_mode_slim_keeps_only_hit_line() -> None:
    shaped, evidence_records = apply_output_mode(_sample_output(), "slim")

    evidence_lines = shaped["events"][0]["evidence"][0]["lines"]
    assert evidence_lines == [{"idx": 101, "text": "ERROR memory init failed"}]
    assert evidence_records[0]["event_id"] == "evt-1"
    validate_output(shaped)


def test_apply_output_mode_tiny_removes_lines() -> None:
    shaped, evidence_records = apply_output_mode(_sample_output(), "tiny")

    evidence = shaped["events"][0]["evidence"][0]
    assert "lines" not in evidence
    assert evidence["ref"] == "log:seg-1:100-120"
    assert evidence_records[0]["start_line"] == 100
    validate_output(shaped)
