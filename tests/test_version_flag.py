"""Version flag behavior tests."""

from __future__ import annotations

from triage import cli


def test_version_flag_prints_version_and_exits_zero(capsys) -> None:
    exit_code = cli.main(["--version"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out.strip() == "0.1.0"
