"""Stable fingerprinting helpers for deterministic events."""

from __future__ import annotations

import hashlib


def stable_event_fingerprint(event: dict) -> dict[str, str]:
    """Build a stable fingerprint payload for an event."""
    category = str(event.get("category", ""))
    severity = str(event.get("severity", ""))
    extracted = event.get("extracted", {}) or {}
    hit_text = str(event.get("_normalized_hit_text", ""))

    canonical = "|".join(
        [
            category,
            severity,
            hit_text,
            str(extracted.get("module", "")),
            str(extracted.get("file", "")),
            str(extracted.get("line", "")),
        ]
    )

    stable_key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    hash_prefix = stable_key[:12]

    if "assert" in category:
        module = extracted.get("module")
        file_name = extracted.get("file")
        line_no = extracted.get("line")
        if module and file_name and line_no:
            dedupe_group = f"assert:{module}:{file_name}:{line_no}"
        else:
            dedupe_group = f"assert:{hash_prefix}"
    elif "watchdog" in category:
        dedupe_group = f"watchdog:{hash_prefix}"
    elif "reset" in category:
        cause = extracted.get("cause")
        dedupe_group = f"reset:{cause}" if cause else f"reset:{hash_prefix}"
    else:
        dedupe_group = f"{category or 'event'}:{hash_prefix}"

    return {"stable_key": stable_key, "dedupe_group": dedupe_group}

