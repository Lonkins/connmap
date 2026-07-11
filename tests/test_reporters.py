"""JSON, SARIF, and console reporter tests."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from connmap.engine import Analysis, analyze
from connmap.importers import load_config
from connmap.model.graph import DataFlowGraph, build_graph
from connmap.policy import generate_policy
from connmap.report import (
    build_json_report,
    build_sarif_report,
    dumps_json_report,
    dumps_sarif_report,
    render_console,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _vulnerable() -> tuple[DataFlowGraph, Analysis]:
    assistant = load_config(EXAMPLES / "openclaw-vulnerable.json")
    graph = build_graph(assistant)
    return graph, analyze(graph)


def test_json_report_structure_and_serializable() -> None:
    assistant = load_config(EXAMPLES / "openclaw-vulnerable.json")
    graph = build_graph(assistant)
    result = analyze(graph)
    policy = generate_policy(assistant, result)

    report = build_json_report(graph, result, policy)
    assert report["source_format"] == "openclaw"
    assert report["summary"]["connectors"] == 3
    assert report["summary"]["findings"] == len(result.findings)
    assert report["summary"]["roles"]["untrusted_inbound"] == 1
    assert len(report["graph"]["nodes"]) == 3
    assert report["graph"]["edges"]
    assert len(report["findings"]) == len(result.findings)
    assert report["policy"]["connmap_policy_version"] == "1.0"

    # Round-trips through JSON.
    assert json.loads(dumps_json_report(graph, result, policy)) == report


def test_json_report_without_policy() -> None:
    graph, result = _vulnerable()
    report = build_json_report(graph, result)
    assert report["policy"] is None


def test_sarif_report_shape() -> None:
    _, result = _vulnerable()
    sarif = build_sarif_report(result, "examples/openclaw-vulnerable.json")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "connmap"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == len(result.findings)

    first = run["results"][0]
    assert first["ruleId"] in {"confused_deputy", "privilege_escalation", "unmediated_exfil"}
    assert first["level"] == "error"  # critical
    assert first["properties"]["security-severity"] == "9.5"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(".json")
    # Valid JSON.
    assert json.loads(dumps_sarif_report(result, "x.json"))["version"] == "2.1.0"


def test_console_render_reports_findings() -> None:
    graph, result = _vulnerable()
    console = Console(record=True, width=100)
    render_console(graph, result, console)
    text = console.export_text()
    assert "CD-001" in text
    assert "whatsapp" in text
    assert "confused" in text.lower()


def test_console_render_clean() -> None:
    assistant = load_config(EXAMPLES / "openclaw-hardened.json")
    graph = build_graph(assistant)
    console = Console(record=True, width=100)
    render_console(graph, analyze(graph), console)
    assert "clean" in console.export_text().lower()
