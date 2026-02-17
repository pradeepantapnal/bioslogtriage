"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
from triage.normalize import load_and_normalize, normalization_stats
from triage.phases import build_segments, detect_phases
from triage.rules.engine import compile_rules, run_rules
from triage.rules.loader import load_rulepack
from triage.schemas.validate import validate_output

_DEFAULT_RULEPACK = Path(__file__).resolve().parent / "rulepacks" / "faults_v1.yaml"


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--input", required=True, help="Path to log file to triage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument(
        "--rules",
        default=str(_DEFAULT_RULEPACK),
        help="Path to YAML rulepack (default: built-in faults_v1)",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable deterministic rule-based event extraction",
    )

    validation_group = parser.add_mutually_exclusive_group()
    validation_group.add_argument(
        "--validate",
        dest="validate",
        action="store_true",
        default=True,
        help="Validate JSON output against Schema v0 (default: enabled)",
    )
    validation_group.add_argument(
        "--no-validate",
        dest="validate",
        action="store_false",
        help="Disable schema validation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entrypoint for the triage CLI."""
    args = build_parser().parse_args(argv)

    lines = load_and_normalize(args.input)
    phases = detect_phases(lines)
    segments = build_segments(lines, phases)

    events: list[dict] = []
    if not args.no_rules:
        rulepack = load_rulepack(args.rules)
        rules = compile_rules(rulepack)
        events = run_rules(lines, segments, rules)

    boot_timeline: dict[str, object] = {
        "segments": [
            {
                "segment_id": segment.segment_id,
                "start_line": segment.start_line,
                "end_line": segment.end_line,
                "phases": [
                    {
                        "phase": phase.phase,
                        "start_line": phase.start_line,
                        "end_line": phase.end_line,
                        "confidence": phase.confidence,
                    }
                    for phase in segment.phases
                ],
            }
            for segment in segments
        ],
        "boot_outcome": "unknown",
    }

    first_fatal = next((event for event in events if event["severity"] == "fatal"), None)
    if first_fatal is not None:
        boot_timeline["boot_blocking_event_id"] = first_fatal["event_id"]

    output = {
        "schema_version": "0.0.0",
        "normalization": normalization_stats(lines),
        "events": events,
        "llm_enabled": args.llm,
        "boot_timeline": boot_timeline,
    }

    if args.validate:
        try:
            validate_output(output)
        except ValueError as exc:
            print(f"Output validation failed: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
