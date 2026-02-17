"""Command-line interface for bioslogtriage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from triage.config import DEFAULT_MODEL, OLLAMA_HOST
from triage.llm.evidence_pack import build_evidence_pack
from triage.llm.ollama_client import OllamaClient
from triage.llm.repair import repair_llm_synthesis
from triage.llm.synthesis import build_system_prompt, build_user_prompt
from triage.version import __version__
from triage.normalize import load_and_normalize, normalization_stats
from triage.phases import build_segments, detect_phases
from triage.rules.engine import compile_rules, run_rules
from triage.rules.loader import load_rulepack
from triage.schemas.validate import validate_output

_DEFAULT_RULEPACK = Path(__file__).resolve().parent / "rulepacks" / "faults_v1.yaml"
_MRC_RULEPACK = Path(__file__).resolve().parent / "rulepacks" / "mrc_v1.yaml"
_PCIE_RULEPACK = Path(__file__).resolve().parent / "rulepacks" / "pcie_v1.yaml"
_STORAGE_RULEPACK = Path(__file__).resolve().parent / "rulepacks" / "storage_v1.yaml"
_SEVERITY_SCORES = {"fatal": 100, "high": 60, "medium": 30, "low": 10, "info": 1}
_PHASE_PENALTIES = {"SEC": 0, "PEI": 2, "DXE": 4, "BDS": 6}


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(prog="bioslogtriage")
    parser.add_argument("--input", required=False, help="Path to log file to triage")
    parser.add_argument("--llm", action="store_true", help="Enable local Ollama call")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument(
        "--llm-top-k",
        type=int,
        default=5,
        help="Number of highest-ranked events to include in LLM evidence pack (default: 5)",
    )
    parser.add_argument(
        "--llm-max-chars",
        type=int,
        default=12000,
        help="Max serialized character budget for LLM evidence pack (default: 12000)",
    )
    parser.add_argument(
        "--llm-timeout-s",
        type=int,
        default=300,
        help="Timeout in seconds for Ollama generate requests (default: 300)",
    )
    parser.add_argument(
        "--dump-llm-prompt",
        default=None,
        help="Optional path to write the exact LLM prompt sent to Ollama",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print bioslogtriage version and exit",
    )
    parser.add_argument(
        "--rules",
        action="append",
        default=None,
        help="Path to YAML rulepack. Repeat to load multiple packs. Overrides --rulepack when set.",
    )
    parser.add_argument(
        "--rulepack",
        choices=("faults", "mrc", "pcie", "storage", "all"),
        default="all",
        help="Built-in rulepack preset (default: all)",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable deterministic rule-based event extraction",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=10,
        help="Number of lines before/after event hit line to include as evidence context (default: 10)",
    )
    parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="Omit evidence.lines payload and keep only evidence references/ranges",
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


def _boot_blocking_score(event: dict) -> int:
    severity_score = _SEVERITY_SCORES.get(str(event.get("severity", "")).lower(), 0)
    confidence = float(event.get("confidence", 0.0))
    phase = event.get("where", {}).get("phase")
    phase_penalty = _PHASE_PENALTIES.get(phase, 0)
    return severity_score + round(confidence * 20) - phase_penalty


def _select_boot_blocking_event_id(events: list[dict]) -> str | None:
    blocking = [event for event in events if event.get("boot_blocking")]
    if not blocking:
        return None

    selected = max(
        blocking,
        key=lambda event: (
            _boot_blocking_score(event),
            -int(event.get("where", {}).get("line_range", {}).get("start", 10**9)),
        ),
    )
    return selected.get("event_id")


def _select_best_llm_event_id(output: dict) -> str:
    boot_timeline = output.get("boot_timeline")
    if isinstance(boot_timeline, dict):
        boot_blocking_event_id = boot_timeline.get("boot_blocking_event_id")
        if isinstance(boot_blocking_event_id, str) and boot_blocking_event_id:
            return boot_blocking_event_id

    llm_input = output.get("llm_input")
    if isinstance(llm_input, dict):
        selected_events = llm_input.get("selected_events")
        if isinstance(selected_events, list):
            for event in selected_events:
                if isinstance(event, dict):
                    event_id = event.get("event_id")
                    if isinstance(event_id, str) and event_id:
                        return event_id

    return "evt-0"


def _llm_fallback(
    error_type: str,
    message: str,
    detail: str = "",
    model: str = "",
    timeout_s: int = 0,
    prompt_len: int = 0,
    candidate_keys: list[str] | None = None,
) -> dict:
    keys = candidate_keys if candidate_keys is not None else []
    return {
        "overall_confidence": 0.0,
        "executive_summary": "LLM synthesis failed; see errors.",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
        "missing_evidence": [],
        "errors": [
            {
                "type": error_type,
                "message": message,
                "detail": detail,
                "model": model,
                "timeout_s": timeout_s,
                "prompt_len": prompt_len,
                "candidate_keys": keys,
            }
        ],
    }


def _validate_llm_synthesis(llm_synthesis: dict) -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "overall_confidence",
            "executive_summary",
            "root_cause_hypotheses",
            "recommended_next_actions",
            "missing_evidence",
        ],
        "properties": {
            "model_info": {"type": "object", "additionalProperties": True},
            "overall_confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "executive_summary": {"type": "string", "minLength": 1, "maxLength": 2000},
            "root_cause_hypotheses": {
                "type": "array",
                "maxItems": 5,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "title",
                        "confidence",
                        "supporting_event_ids",
                        "reasoning",
                        "next_actions",
                    ],
                    "properties": {
                        "title": {"type": "string", "minLength": 1, "maxLength": 200},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "supporting_event_ids": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        },
                        "reasoning": {"type": "string", "minLength": 1, "maxLength": 2000},
                        "next_actions": {
                            "type": "array",
                            "maxItems": 8,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "action",
                                    "priority",
                                    "expected_signal",
                                    "supporting_event_ids",
                                ],
                                "properties": {
                                    "action": {"type": "string", "minLength": 1, "maxLength": 300},
                                    "priority": {"type": "string", "enum": ["P0", "P1", "P2"]},
                                    "expected_signal": {
                                        "type": "string",
                                        "minLength": 1,
                                        "maxLength": 300,
                                    },
                                    "supporting_event_ids": {
                                        "type": "array",
                                        "minItems": 1,
                                        "items": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "recommended_next_actions": {
                "type": "array",
                "maxItems": 10,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["action", "priority", "expected_signal", "supporting_event_ids"],
                    "properties": {
                        "action": {"type": "string", "minLength": 1, "maxLength": 300},
                        "priority": {"type": "string", "enum": ["P0", "P1", "P2"]},
                        "expected_signal": {"type": "string", "minLength": 1, "maxLength": 300},
                        "supporting_event_ids": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        },
                    },
                },
            },
            "missing_evidence": {
                "type": "array",
                "maxItems": 10,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["need", "why", "how", "priority", "supporting_event_ids"],
                    "properties": {
                        "need": {"type": "string", "minLength": 1, "maxLength": 200},
                        "why": {"type": "string", "minLength": 1, "maxLength": 300},
                        "how": {"type": "string", "minLength": 1, "maxLength": 300},
                        "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                        "supporting_event_ids": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        },
                    },
                },
            },
            "errors": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": True},
            },
        },
    }

    try:
        import jsonschema
    except ModuleNotFoundError:
        required = {
            "overall_confidence",
            "executive_summary",
            "root_cause_hypotheses",
            "recommended_next_actions",
            "missing_evidence",
        }
        missing = required - set(llm_synthesis.keys())
        if missing:
            raise ValueError(f"missing required keys {sorted(missing)}")
        return

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(llm_synthesis), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise ValueError(f"llm_synthesis validation failed at {path}: {first.message}")

def main(argv: list[str] | None = None) -> int:
    """Entrypoint for the triage CLI."""
    args = build_parser().parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    if not args.input:
        print("--input is required unless --version is provided", file=sys.stderr)
        return 2

    lines = load_and_normalize(args.input)
    phases = detect_phases(lines)
    segments = build_segments(lines, phases)

    events: list[dict] = []
    if not args.no_rules:
        if args.rules:
            rulepack_paths = args.rules
        else:
            preset_map = {
                "faults": [str(_DEFAULT_RULEPACK)],
                "mrc": [str(_MRC_RULEPACK)],
                "pcie": [str(_PCIE_RULEPACK)],
                "storage": [str(_STORAGE_RULEPACK)],
                "all": [str(_DEFAULT_RULEPACK), str(_MRC_RULEPACK), str(_PCIE_RULEPACK), str(_STORAGE_RULEPACK)],
            }
            rulepack_paths = preset_map[args.rulepack]

        rules = []
        for rulepack_path in rulepack_paths:
            rulepack = load_rulepack(rulepack_path)
            rules.extend(compile_rules(rulepack))

        events = run_rules(
            lines,
            segments,
            rules,
            context_lines=max(0, args.context_lines),
            include_evidence_lines=(not args.no_evidence),
        )

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
        "boot_blocking_event_id": _select_boot_blocking_event_id(events),
    }

    output = {
        "schema_version": "0.1.0",
        "normalization": normalization_stats(lines),
        "events": events,
        "llm_enabled": args.llm,
        "boot_timeline": boot_timeline,
    }

    if args.llm:
        llm_ok = False
        model_name = args.model
        timeout_s = max(1, args.llm_timeout_s)
        prompt_len = 0
        candidate_keys: list[str] = []
        try:
            evidence_pack = build_evidence_pack(
                output,
                top_k=max(0, args.llm_top_k),
                max_chars=max(1, args.llm_max_chars),
            )
            output["llm_input"] = evidence_pack

            user_prompt = build_user_prompt(evidence_pack)
            prompt_len = len(user_prompt)
            if args.dump_llm_prompt:
                Path(args.dump_llm_prompt).write_text(user_prompt, encoding="utf-8")

            client = OllamaClient(host=args.ollama_host, model=model_name, timeout_s=timeout_s)
            candidate = client.generate_json(
                system=build_system_prompt(),
                user=user_prompt,
                schema={"type": "object"},
            )
            if not isinstance(candidate, dict):
                raise ValueError("LLM returned non-object JSON")
            candidate_keys = sorted(candidate.keys())
            if isinstance(candidate.get("llm_synthesis"), dict):
                candidate = candidate["llm_synthesis"]
                candidate_keys = sorted(candidate.keys())
            if "evidence_pack" in candidate or "selected_events" in candidate:
                raise ValueError("LLM echoed input evidence pack instead of producing llm_synthesis")
            candidate = repair_llm_synthesis(candidate, best_event_id=_select_best_llm_event_id(output))
            _validate_llm_synthesis(candidate)
            output["llm_synthesis"] = candidate
            llm_ok = True
        except Exception as exc:  # noqa: BLE001
            output["llm_synthesis"] = _llm_fallback(
                error_type=exc.__class__.__name__,
                message="Failed to generate or validate LLM synthesis",
                detail=str(exc),
                model=model_name,
                timeout_s=timeout_s,
                prompt_len=prompt_len,
                candidate_keys=candidate_keys,
            )

        if not llm_ok:
            output["llm_synthesis"] = output.get(
                "llm_synthesis",
                _llm_fallback(
                    error_type="RuntimeError",
                    message="Failed to generate or validate LLM synthesis",
                    detail="LLM synthesis status unknown",
                    model=model_name,
                    timeout_s=timeout_s,
                    prompt_len=prompt_len,
                    candidate_keys=candidate_keys,
                ),
            )

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
