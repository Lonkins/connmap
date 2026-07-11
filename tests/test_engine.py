"""Threat engine: confused-deputy, escalation, and latent-exfil detection."""

from __future__ import annotations

from pathlib import Path

from connmap.engine import Severity, ThreatKind, analyze
from connmap.importers import load_config
from connmap.model.connector import Assistant, Connector, Route
from connmap.model.graph import build_graph

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _analyze_example(name: str) -> object:
    return analyze(build_graph(load_config(EXAMPLES / name)))


def test_vulnerable_openclaw_reports_confused_deputy() -> None:
    result = analyze(build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json")))
    assert not result.clean
    assert result.highest_severity is Severity.CRITICAL

    cds = [f for f in result.findings if f.kind is ThreatKind.CONFUSED_DEPUTY]
    exfil_via_http = [f for f in cds if f.sink == "http"]
    assert exfil_via_http, "expected a confused-deputy path exfiltrating via http"
    finding = exfil_via_http[0]
    assert finding.chain == ("whatsapp", "files", "http")
    assert "files" in finding.pivots
    assert finding.code.startswith("CD-")
    # The narrative names the exact chain.
    assert "whatsapp → files → http" in finding.narrative


def test_hardened_openclaw_is_clean() -> None:
    result = analyze(build_graph(load_config(EXAMPLES / "openclaw-hardened.json")))
    assert result.clean
    assert result.findings == ()


def test_mcp_reports_privilege_escalation() -> None:
    result = analyze(build_graph(load_config(EXAMPLES / "mcp-vulnerable.json")))
    pes = [f for f in result.findings if f.kind is ThreatKind.PRIVILEGE_ESCALATION]
    assert any(f.sink == "shell" and f.source == "telegram" for f in pes)
    assert all(f.severity is Severity.CRITICAL for f in pes)


def test_reply_exfil_is_detected() -> None:
    # WhatsApp both receives and sends, so reading a file and replying is exfil.
    result = analyze(build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json")))
    cds = [f for f in result.findings if f.kind is ThreatKind.CONFUSED_DEPUTY]
    assert any(f.source == "whatsapp" and f.sink == "whatsapp" for f in cds)


def test_latent_exfil_without_inbound() -> None:
    config = Assistant(
        name="latent",
        connectors=(
            Connector(id="files", kind="files"),
            Connector(id="http", kind="http_out"),
        ),
    )
    result = analyze(build_graph(config))
    exfil = [f for f in result.findings if f.kind is ThreatKind.UNMEDIATED_EXFIL]
    assert len(exfil) == 1
    assert exfil[0].chain == ("files", "http")
    assert exfil[0].severity is Severity.HIGH


def test_mediated_route_blocks_escalation() -> None:
    config = Assistant(
        name="mediated-shell",
        connectors=(
            Connector(id="wa", kind="whatsapp"),
            Connector(id="sh", kind="shell"),
        ),
        routes=(Route(source="wa", target="sh", mediated=True),),
    )
    result = analyze(build_graph(config))
    assert result.clean


def test_neutral_config_is_clean() -> None:
    config = Assistant(name="calm", connectors=(Connector(id="x", kind="mystery"),))
    result = analyze(build_graph(config))
    assert result.clean


def test_analysis_is_deterministic() -> None:
    graph = build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json"))
    assert analyze(graph).findings == analyze(graph).findings


def test_codes_are_unique_and_formatted() -> None:
    result = analyze(build_graph(load_config(EXAMPLES / "mcp-vulnerable.json")))
    codes = [f.code for f in result.findings]
    assert len(codes) == len(set(codes))
    for code in codes:
        prefix, _, number = code.partition("-")
        assert prefix in {"CD", "PE", "EX"}
        assert number.isdigit()


def test_severity_counts_and_sorting() -> None:
    result = analyze(build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json")))
    counts = result.severity_counts()
    assert counts[Severity.CRITICAL] == len(result.findings)
    ordered = result.sorted_by_severity()
    assert ordered[0].severity is Severity.CRITICAL
