"""CLI behavior tests."""

from __future__ import annotations

import json

from triage import cli


def test_cli_help_includes_input_flag() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    assert "--input" in help_text


def test_cli_summarizes_input_file(tmp_path, monkeypatch, capsys) -> None:
    log_file = tmp_path / "test.log"
    log_file.write_text("Boot OK\nWARN: voltage low\nERROR: memory init failed\n", encoding="utf-8")

    monkeypatch.setattr("sys.argv", ["bioslogtriage", "--input", str(log_file)])
    cli.main()

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed == {"error_count": 1, "line_count": 3, "warning_count": 1}
