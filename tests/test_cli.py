"""CLI behavior tests."""

from __future__ import annotations

import json

from triage import cli


def test_cli_help_includes_input_flag() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    assert "--input" in help_text


def test_cli_outputs_stub_json(tmp_path, capsys) -> None:
    log_file = tmp_path / "test.log"
    log_file.write_text("Boot OK\nWARN: voltage low\nERROR: memory init failed\n", encoding="utf-8")

    exit_code = cli.main(["--input", str(log_file)])

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert exit_code == 0
    assert parsed["schema_version"] == "0.0.0"
    assert parsed["normalization"]["line_count"] == 3
    assert parsed["events"] == []
    assert parsed["llm_enabled"] is False
