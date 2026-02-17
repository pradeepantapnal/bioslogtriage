"""Prompt builders for grounded LLM synthesis."""

from __future__ import annotations

import json


def build_system_prompt() -> str:
    """Build system prompt for strict, grounded JSON synthesis."""
    return (
        "You are a BIOS log triage synthesis engine. "
        "Return ONLY a JSON object matching the llm_synthesis schema. "
        "Use ONLY facts present in the provided llm_input JSON evidence pack. "
        "Do not invent or infer external facts. "
        "Every root_cause_hypothesis and every action must include supporting_event_ids "
        "that reference event_id values from llm_input.selected_events."
    )


def build_user_prompt(llm_input: dict) -> str:
    """Build compact user prompt containing evidence-pack JSON."""
    compact = json.dumps(llm_input, ensure_ascii=False, separators=(",", ":"))
    return (
        "Synthesize grounded triage findings from this llm_input evidence pack. "
        "Output JSON only.\n"
        f"{compact}"
    )
