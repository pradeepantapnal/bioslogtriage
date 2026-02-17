"""Minimal Ollama API client for local inference."""

from __future__ import annotations

import json
from typing import Any


def _post(url: str, payload: dict[str, Any], timeout_s: int, model: str) -> Any:
    """Call requests.post lazily so tests can run without installed dependency."""
    try:
        import requests
    except ModuleNotFoundError as exc:
        raise RuntimeError("The 'requests' package is required for OllamaClient") from exc

    try:
        return requests.post(url, json=payload, timeout=timeout_s)
    except requests.ReadTimeout as exc:
        prompt_len = len(str(payload.get("prompt", "")))
        raise RuntimeError(
            f"Ollama request timed out (model={model}, timeout_s={timeout_s}, prompt_chars={prompt_len}). "
            "Try reducing --llm-max-chars or --llm-top-k, or increase --llm-timeout-s."
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to connect to Ollama at {url}: {exc}") from exc


class OllamaClient:
    """Simple wrapper around the Ollama `/api/generate` endpoint."""

    def __init__(self, host: str, model: str, timeout_s: int = 60) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Generate a JSON response from a local Ollama model."""
        _ = schema
        payload = {
            "model": self.model,
            "prompt": user,
            "system": system,
            "stream": False,
            "format": "json",
        }
        url = f"{self.host}/api/generate"

        response = _post(url, payload, self.timeout_s, self.model)

        if response.status_code != 200:
            raise RuntimeError(
                f"Ollama request failed with HTTP {response.status_code}: {response.text}"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise ValueError("Ollama returned invalid JSON in HTTP response body") from exc

        raw_result = body.get("response") if isinstance(body, dict) else None
        if isinstance(raw_result, dict):
            return raw_result

        if not isinstance(raw_result, str):
            raise ValueError("Ollama response does not contain a JSON string in 'response'")

        try:
            parsed = json.loads(raw_result)
        except json.JSONDecodeError as exc:
            raise ValueError("Ollama returned invalid JSON content in 'response'") from exc

        if not isinstance(parsed, dict):
            raise ValueError("Ollama JSON content is not an object")

        return parsed
