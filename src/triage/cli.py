"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json

from triage.config import DEFAULT_MODEL, OLLAMA_HOST


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--input", required=True, help="Path to log file to triage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
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

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
