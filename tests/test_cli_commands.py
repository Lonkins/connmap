"""CLI integration tests for `connmap analyze` and `connmap policy`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from connmap.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
VULNERABLE = str(EXAMPLES / "openclaw-vulnerable.json")
HARDENED = str(EXAMPLES / "openclaw-hardened.json")


def test_analyze_vulnerable_exits_nonzero_and_reports() -> None:
    result = runner.invoke(app, ["analyze", VULNERABLE])
    assert result.exit_code == 1
    assert "CD-001" in result.output


def test_analyze_hardened_is_clean_and_exits_zero() -> None:
    result = runner.invoke(app, ["analyze", HARDENED])
    assert result.exit_code == 0
    assert "clean" in result.output.lower()


def test_analyze_exit_zero_flag() -> None:
    result = runner.invoke(app, ["analyze", VULNERABLE, "--exit-zero"])
    assert result.exit_code == 0


def test_analyze_quiet_suppresses_report_but_still_exits_nonzero() -> None:
    result = runner.invoke(app, ["analyze", VULNERABLE, "--quiet"])
    assert result.exit_code == 1
    assert "CD-001" not in result.output


def test_analyze_writes_artifacts(tmp_path: Path) -> None:
    json_out = tmp_path / "report.json"
    sarif_out = tmp_path / "report.sarif"
    policy_out = tmp_path / "policy.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            VULNERABLE,
            "--json",
            str(json_out),
            "--sarif",
            str(sarif_out),
            "--policy",
            str(policy_out),
            "--quiet",
        ],
    )
    assert result.exit_code == 1
    assert json.loads(json_out.read_text())["source_format"] == "openclaw"
    assert json.loads(sarif_out.read_text())["version"] == "2.1.0"
    assert json.loads(policy_out.read_text())["connmap_policy_version"] == "1.0"


def test_analyze_bad_path_exits_two() -> None:
    result = runner.invoke(app, ["analyze", str(EXAMPLES / "nope.json")])
    assert result.exit_code == 2
    assert "error" in result.output.lower()


def test_analyze_explicit_importer_override() -> None:
    result = runner.invoke(app, ["analyze", VULNERABLE, "--importer", "mcp"])
    assert result.exit_code == 2  # OpenClaw doc rejected by MCP importer


def test_policy_command_prints_json() -> None:
    result = runner.invoke(app, ["policy", VULNERABLE])
    assert result.exit_code == 0
    assert json.loads(result.output)["connmap_policy_version"] == "1.0"


def test_policy_command_writes_file(tmp_path: Path) -> None:
    out = tmp_path / "policy.json"
    result = runner.invoke(app, ["policy", VULNERABLE, "--out", str(out)])
    assert result.exit_code == 0
    assert json.loads(out.read_text())["default"] == "allow"
