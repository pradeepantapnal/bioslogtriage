"""Schema loading and validation utilities for triage CLI output."""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
from importlib import resources


_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def load_schema() -> dict:
    """Load and return the triage output JSON schema."""
    schema_path = resources.files("triage.schemas").joinpath("triage.schema.json")
    with schema_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_without_jsonschema(data: dict) -> None:
    """Minimal fallback validation when jsonschema is unavailable."""
    required_keys = {"schema_version", "normalization", "events", "llm_enabled"}
    missing = required_keys - data.keys()
    if missing:
        raise ValueError(f"Schema validation failed at <root>: missing required keys {sorted(missing)}")

    if not isinstance(data["schema_version"], str) or not _VERSION_PATTERN.match(data["schema_version"]):
        raise ValueError("Schema validation failed at schema_version: must match X.Y.Z")

    normalization = data["normalization"]
    if not isinstance(normalization, dict):
        raise ValueError("Schema validation failed at normalization: must be an object")

    line_count = normalization.get("line_count")
    if not isinstance(line_count, int) or line_count < 0:
        raise ValueError("Schema validation failed at normalization.line_count: must be integer >= 0")

    if not isinstance(data["events"], list):
        raise ValueError("Schema validation failed at events: must be an array")
    if any(not isinstance(item, dict) for item in data["events"]):
        raise ValueError("Schema validation failed at events: each item must be an object")

    if not isinstance(data["llm_enabled"], bool):
        raise ValueError("Schema validation failed at llm_enabled: must be a boolean")


def validate_output(data: dict) -> None:
    """Validate CLI output against schema.

    Raises:
        ValueError: If the output does not conform to the schema.
    """
    schema = load_schema()

    if importlib.util.find_spec("jsonschema") is None:
        _validate_without_jsonschema(data)
        return

    jsonschema = importlib.import_module("jsonschema")
    validator = jsonschema.Draft202012Validator(schema)

    errors = sorted(validator.iter_errors(data), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise ValueError(f"Schema validation failed at {path}: {first.message}")
