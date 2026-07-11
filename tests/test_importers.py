"""Importer tests: OpenClaw, MCP, auto-detection, and boundary errors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from connmap.importers import (
    ImporterError,
    available_formats,
    get_importer,
    load_config,
    parse_document,
)
from connmap.importers.tools import capabilities_from_tools, make_connector
from connmap.model.graph import EdgeKind, build_graph
from connmap.model.trust import Capability, TrustRole

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_openclaw_vulnerable_imports() -> None:
    assistant = load_config(EXAMPLES / "openclaw-vulnerable.json")
    assert assistant.source_format == "openclaw"
    assert {c.id for c in assistant.connectors} == {"whatsapp", "files", "http"}
    assert assistant.connector("whatsapp").trust_role is TrustRole.UNTRUSTED_INBOUND
    assert assistant.connector("files").trust_role is TrustRole.SENSITIVE_SOURCE
    assert assistant.connector("http").trust_role is TrustRole.ACTION_OR_EXFIL
    # Permissive routing -> no declared routes.
    assert assistant.routes == ()


def test_openclaw_vulnerable_has_confused_deputy_path() -> None:
    graph = build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json"))
    pairs = {(e.source, e.target): e.kind for e in graph.edges}
    assert pairs[("whatsapp", "files")] is EdgeKind.TRIGGER
    assert pairs[("files", "http")] is EdgeKind.DATA


def test_openclaw_hardened_uses_closed_world_routes() -> None:
    assistant = load_config(EXAMPLES / "openclaw-hardened.json")
    assert len(assistant.routes) == 2
    graph = build_graph(assistant)
    assert graph.edge("files", "http").mediated is True
    # The direct inbound->sink hop is not declared, so it does not exist.
    with pytest.raises(KeyError):
        graph.edge("whatsapp", "http")


def test_mcp_vulnerable_imports() -> None:
    assistant = load_config(EXAMPLES / "mcp-vulnerable.json")
    assert assistant.source_format == "mcp"
    assert assistant.connector("telegram").trust_role is TrustRole.UNTRUSTED_INBOUND
    assert assistant.connector("filesystem").trust_role is TrustRole.SENSITIVE_SOURCE
    assert assistant.connector("shell").has(Capability.EXECUTE)
    assert assistant.routes == ()  # MCP is permissive


def test_mcp_shell_escalation_edges() -> None:
    graph = build_graph(load_config(EXAMPLES / "mcp-vulnerable.json"))
    kinds = {(e.source, e.target): e.kind for e in graph.edges}
    assert kinds[("shell", "filesystem")] is EdgeKind.ESCALATION


def test_autodetection_picks_right_importer() -> None:
    openclaw = json.loads((EXAMPLES / "openclaw-vulnerable.json").read_text())
    mcp = json.loads((EXAMPLES / "mcp-vulnerable.json").read_text())
    assert parse_document(openclaw).source_format == "openclaw"
    assert parse_document(mcp).source_format == "mcp"


def test_explicit_format_override_is_used() -> None:
    openclaw = json.loads((EXAMPLES / "openclaw-vulnerable.json").read_text())
    # Forcing the MCP importer on an OpenClaw doc fails cleanly.
    with pytest.raises(ImporterError, match="mcpServers"):
        parse_document(openclaw, fmt="mcp")


def test_available_formats_and_unknown() -> None:
    assert set(available_formats()) == {"openclaw", "mcp"}
    with pytest.raises(ImporterError, match="unknown format"):
        get_importer("toml")


def test_undetectable_document_raises() -> None:
    with pytest.raises(ImporterError, match="could not detect"):
        parse_document({"totally": "unrelated"})


def test_missing_file_raises() -> None:
    with pytest.raises(ImporterError, match="not found"):
        load_config(EXAMPLES / "does-not-exist.json")


def test_bad_extension_raises(tmp_path: Path) -> None:
    p = tmp_path / "config.yaml"
    p.write_text("connectors: []")
    with pytest.raises(ImporterError, match="unsupported config extension"):
        load_config(p)


def test_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text("{not valid json")
    with pytest.raises(ImporterError, match="invalid JSON"):
        load_config(p)


def test_non_object_root_raises(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(ImporterError, match="must be a JSON object"):
        load_config(p)


def test_openclaw_no_connectors_raises() -> None:
    with pytest.raises(ImporterError, match="no connectors"):
        parse_document({"openclaw_version": "1.0", "connectors": []})


def test_openclaw_disabled_connector_excluded() -> None:
    assistant = parse_document(
        {
            "connectors": [
                {"id": "wa", "type": "whatsapp"},
                {"id": "sh", "type": "shell", "enabled": False},
            ]
        }
    )
    assert {c.id for c in assistant.connectors} == {"wa"}


def test_openclaw_connector_missing_id_raises() -> None:
    with pytest.raises(ImporterError, match="missing a string id"):
        parse_document({"connectors": [{"type": "whatsapp"}]})


def test_openclaw_connector_entry_not_object_raises() -> None:
    with pytest.raises(ImporterError, match="not an object"):
        parse_document({"connectors": ["not-a-dict"]})


def test_openclaw_all_disabled_raises() -> None:
    with pytest.raises(ImporterError, match="no enabled connectors"):
        parse_document({"connectors": [{"id": "sh", "type": "shell", "enabled": False}]})


def test_mcp_server_without_tools_uses_kind_hint() -> None:
    assistant = parse_document({"mcpServers": {"vault": {"connmap": {"kind": "files"}}}})
    assert assistant.connector("vault").trust_role is TrustRole.SENSITIVE_SOURCE


def test_tools_to_capabilities() -> None:
    caps = capabilities_from_tools(["Read_File", "fetch", "unknown_tool"])
    assert caps == frozenset({Capability.READ_SENSITIVE, Capability.NETWORK_OUT})


def test_make_connector_unions_kind_and_tools() -> None:
    # Unknown kind, but tools reveal the capability -> role is still correct.
    c = make_connector(connector_id="x", name="X", raw_kind="mystery", tools=["fetch"])
    assert c.trust_role is TrustRole.ACTION_OR_EXFIL
