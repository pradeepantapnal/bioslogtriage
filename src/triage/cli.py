"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
import sys

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
from triage.normalize import load_and_normalize, normalization_stats
from triage.phases import build_segments, detect_phases
from triage.schemas.validate import validate_output


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--input", required=True, help="Path to log file to triage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")

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

    output = {
        "schema_version": "0.0.0",
        "normalization": normalization_stats(lines),
        "events": [],
        "llm_enabled": args.llm,
        "boot_timeline": {
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
        },
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
