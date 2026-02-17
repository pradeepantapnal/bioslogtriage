"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
from typing import Any

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
from triage.llm.ollama_client import OllamaClient


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    return parser


def main() -> None:
    """Entrypoint for the triage CLI."""
    args = build_parser().parse_args()

    if not args.llm:
        print("bioslogtriage CLI")
        return

    client = OllamaClient(host=args.ollama_host, model=args.model)
    result: dict[str, Any] = client.generate_json(
        system="You are a BIOS log triage assistant.",
        user="Summarize this sample log and output JSON.",
        schema={"type": "object"},
    )
    print(json.dumps(result, indent=2, sort_keys=True))
