"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
import sys

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
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

    with open(args.input, "r", encoding="utf-8", errors="replace") as handle:
        log_text = handle.read()

    output = {
        "schema_version": "0.0.0",
        "normalization": {"line_count": len(log_text.splitlines())},
        "events": [],
        "llm_enabled": args.llm,
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
