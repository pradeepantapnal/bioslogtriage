"""Rule loading utilities."""

from __future__ import annotations

import json
from pathlib import Path

_REQUIRED_RULE_KEYS = {
    "id",
    "category",
    "severity",
    "regex",
    "required_phase",
}



def load_rulepack(path: str) -> dict:
    """Load and minimally validate a YAML rulepack."""
    rulepack_path = Path(path)
    with rulepack_path.open("r", encoding="utf-8") as handle:
        raw = handle.read()

    try:
        import yaml  # type: ignore

        data = yaml.safe_load(raw)
    except ModuleNotFoundError:
        # Fallback parser for offline test environments when PyYAML is unavailable.
        # JSON is valid YAML, and built-in rulepacks use this compatible subset.
        data = json.loads(raw)

    if not isinstance(data, dict):
        raise ValueError("Rulepack must be a mapping")
    if "version" not in data:
        raise ValueError("Rulepack is missing required key: version")
    if "rules" not in data or not isinstance(data["rules"], list):
        raise ValueError("Rulepack is missing required list: rules")

    for idx, rule in enumerate(data["rules"], start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule #{idx} must be a mapping")

        missing = _REQUIRED_RULE_KEYS - rule.keys()
        if missing:
            raise ValueError(f"Rule #{idx} is missing required keys: {sorted(missing)}")

        if "confidence" not in rule and "base_confidence" not in rule:
            raise ValueError(f"Rule #{idx} must define confidence or base_confidence")

        if rule["required_phase"] is not None and rule["required_phase"] not in {"SEC", "PEI", "DXE", "BDS"}:
            raise ValueError(f"Rule #{idx} has invalid required_phase: {rule['required_phase']}")

        extracts = rule.get("extracts", {})
        if not isinstance(extracts, dict):
            raise ValueError(f"Rule #{idx} has invalid extracts; expected mapping")

    return data
