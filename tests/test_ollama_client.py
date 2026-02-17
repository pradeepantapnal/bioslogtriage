"""Unit tests for Ollama client."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from triage.llm.ollama_client import OllamaClient, _post


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: object | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> object:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def test_generate_json_posts_expected_payload() -> None:
    client = OllamaClient(host="http://localhost:11434", model="qwen2.5:7b")

    with patch(
        "triage.llm.ollama_client._post",
        return_value=_FakeResponse(payload={"response": '{"ok": true}'}),
    ) as post:
        out = client.generate_json(system="sys", user="usr", schema={"type": "object"})

    assert out == {"ok": True}
    post.assert_called_once_with(
        "http://localhost:11434/api/generate",
        {
            "model": "qwen2.5:7b",
            "prompt": "usr",
            "system": "sys",
            "stream": False,
            "format": "json",
        },
        60,
        "qwen2.5:7b",
    )


def test_generate_json_invalid_json_raises() -> None:
    client = OllamaClient(host="http://localhost:11434", model="qwen2.5:7b")

    with patch(
        "triage.llm.ollama_client._post",
        return_value=_FakeResponse(payload={"response": "not-json"}),
    ):
        with pytest.raises(ValueError, match="invalid JSON content"):
            client.generate_json(system="sys", user="usr", schema={"type": "object"})


def test_post_read_timeout_has_actionable_message() -> None:
    requests = pytest.importorskip("requests")

    with patch("requests.post", side_effect=requests.ReadTimeout("slow")):
        with pytest.raises(RuntimeError, match="llm-max-chars") as exc:
            _post(
                "http://localhost:11434/api/generate",
                {"prompt": "abc" * 20},
                timeout_s=123,
                model="qwen2.5:3b",
            )

    msg = str(exc.value)
    assert "model=qwen2.5:3b" in msg
    assert "timeout_s=123" in msg
    assert "prompt_chars=60" in msg
