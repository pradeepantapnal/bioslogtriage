"""Prompt builders for grounded LLM synthesis."""

from __future__ import annotations

import json


def build_system_prompt() -> str:
    """Build system prompt for strict, grounded JSON synthesis."""
    return (
        "You are a BIOS log triage synthesis engine. "
        "You are generating ONLY the 'llm_synthesis' JSON object. "
        "Do NOT return the input evidence pack. "
        "Do NOT include keys: evidence_pack, evidence_pack_meta, llm_input, selected_events. "
        "Use ONLY facts present in the provided evidence pack JSON. "
        "Do not invent or infer external facts. "
        "Return EXACTLY these top-level keys: overall_confidence, executive_summary, "
        "root_cause_hypotheses, recommended_next_actions, missing_evidence. "
        "Every hypothesis and every action must include supporting_event_ids that reference "
        "event_id values from the provided events. "
        "If uncertain, still output all keys; use low confidence and empty arrays. "
        "Return JSON only. No markdown. No extra keys."
    )


def build_user_prompt(llm_input: dict) -> str:
    """Build compact user prompt containing evidence-pack JSON."""
    compact = json.dumps(llm_input, ensure_ascii=False, separators=(",", ":"))
    output_template = {
        "overall_confidence": 0.2,
        "executive_summary": "",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
        "missing_evidence": [],
    }
    template_json = json.dumps(output_template, ensure_ascii=False, separators=(",", ":"))
    return (
        "INPUT EVIDENCE (do not copy to output):\n"
        f"{compact}\n"
        "OUTPUT TEMPLATE (fill values, keep keys exactly):\n"
        f"{template_json}\n"
        "Do not add any other keys."
    )
