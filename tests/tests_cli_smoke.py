"""Smoke test for CLI JSON output."""

from __future__ import annotations

import json

from triage import cli


def test_cli_main_prints_json(tmp_path, capsys) -> None:
    fixture_path = tmp_path / "fixture.log"
    fixture_path.write_text("line one\nline two\n", encoding="utf-8")

    cli.main(["--input", str(fixture_path)])

    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert "schema_version" in parsed
