"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
from typing import Any

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
from triage.ingest import read_log
from triage.llm.ollama_client import OllamaClient
from triage.normalize import normalize_log
from triage.rules.engine import summarize_log


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--input", help="Path to log file to triage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    return parser


def main() -> None:
    """Entrypoint for the triage CLI."""
    args = build_parser().parse_args()

    if not args.input and not args.llm:
        print("bioslogtriage CLI")
        return

    log_text = ""
    if args.input:
        log_text = normalize_log(read_log(args.input))

    if not args.llm:
        print(json.dumps(summarize_log(log_text), indent=2, sort_keys=True))
        return

    client = OllamaClient(host=args.ollama_host, model=args.model)
    result: dict[str, Any] = client.generate_json(
        system="You are a BIOS log triage assistant.",
        user=(
            "Summarize this BIOS log and output JSON with fields: "
            "summary, issues, severity.\n\n"
            f"Log:\n{log_text}"
        ),
        schema={"type": "object"},
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
