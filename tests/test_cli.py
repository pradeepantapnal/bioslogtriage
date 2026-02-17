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
    assert parsed["schema_version"] == "0.1.0"
    assert parsed["normalization"]["line_count"] == 3
    assert parsed["events"] == []
    assert parsed["llm_enabled"] is False


def test_cli_writes_main_output_with_out_flag(tmp_path, capsys) -> None:
    log_file = tmp_path / "test.log"
    out_file = tmp_path / "result.json"
    log_file.write_text("ERROR: memory init failed\n", encoding="utf-8")

    exit_code = cli.main(["--input", str(log_file), "--out", str(out_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "0.1.0"


def test_cli_writes_evidence_jsonl_artifact(tmp_path, capsys) -> None:
    log_file = tmp_path / "test.log"
    out_file = tmp_path / "result.json"
    evidence_file = tmp_path / "evidence.jsonl"
    log_file.write_text("line1\nASSERT: memory init failed\nline3\n", encoding="utf-8")

    exit_code = cli.main(
        [
            "--input",
            str(log_file),
            "--rules",
            "src/triage/rulepacks/faults_v1.yaml",
            "--out",
            str(out_file),
            "--evidence-out",
            str(evidence_file),
        ]
    )

    _ = capsys.readouterr()
    assert exit_code == 0
    assert out_file.exists()
    assert evidence_file.exists()

    lines = [line for line in evidence_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    first = json.loads(lines[0])
    assert first["event_id"].startswith("evt-")
    assert {"ref", "start_line", "end_line", "lines"} <= set(first.keys())
