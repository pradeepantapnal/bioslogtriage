"""Prompt builders for two-pass grounded LLM analysis."""

from __future__ import annotations

import json


def build_facts_system_prompt() -> str:
    """Build system prompt for extracting grounded facts from llm_input."""
    return (
        "You are a BIOS log evidence extraction engine. "
        "Output JSON ONLY with keys: overall_grounding_confidence, facts. "
        "Extract only direct observations supported by llm_input. "
        "No speculation or inferred external knowledge. "
        "Do not use uncertain language like probably/maybe. "
        "Every fact must include supporting_event_ids using event_id values from selected_events. "
        "Facts should be concise and objective. "
        "Return no markdown, no prose, and no extra keys."
    )


def build_facts_user_prompt(llm_input: dict) -> str:
    """Build facts-pass user prompt with compact llm_input payload."""
    compact = json.dumps(llm_input, ensure_ascii=False, separators=(",", ":"))
    template = {
        "overall_grounding_confidence": 0.0,
        "facts": [
            {
                "fact": "",
                "supporting_event_ids": ["evt-1"],
                "confidence": 0.0,
            }
        ],
    }
    template_json = json.dumps(template, ensure_ascii=False, separators=(",", ":"))
    return (
        "INPUT LLM EVIDENCE PACK (do not copy to output):\n"
        f"{compact}\n"
        "OUTPUT TEMPLATE (keys must match exactly):\n"
        f"{template_json}\n"
        "Return JSON only with those top-level keys."
    )


def build_synthesis_system_prompt() -> str:
    """Build system prompt for synthesis from llm_facts only."""
    return (
        "You are a BIOS log triage synthesis engine. "
        "Output JSON ONLY with keys: overall_confidence, executive_summary, "
        "root_cause_hypotheses, recommended_next_actions, missing_evidence. "
        "Use ONLY the provided llm_facts JSON. Do not use llm_input directly. "
        "Every hypothesis/action/missing_evidence entry must cite supporting_event_ids from facts. "
        "If uncertain, keep arrays empty but still return all required keys. "
        "No markdown. No extra keys."
    )


def build_synthesis_user_prompt(llm_facts: dict) -> str:
    """Build synthesis-pass user prompt with compact llm_facts payload."""
    compact = json.dumps(llm_facts, ensure_ascii=False, separators=(",", ":"))
    template = {
        "overall_confidence": 0.0,
        "executive_summary": "",
        "root_cause_hypotheses": [],
        "recommended_next_actions": [],
        "missing_evidence": [],
    }
    template_json = json.dumps(template, ensure_ascii=False, separators=(",", ":"))
    return (
        "INPUT LLM FACTS (source of truth; do not copy verbatim):\n"
        f"{compact}\n"
        "OUTPUT TEMPLATE (fill values; keep keys exactly):\n"
        f"{template_json}\n"
        "Return JSON only."
    )
