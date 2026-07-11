"""Importer for the generic MCP-integration config schema.

The de-facto MCP client config maps server names to launch specs under
``mcpServers``. connmap reads each server as a connector, deriving capabilities
from its declared ``tools`` (the real capability signal for MCP) and an optional
``connmap`` hint block (``kind``, ``trusted``, ``label``). MCP clients let the
model call any exposed tool, so the graph uses the permissive default.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from connmap.importers.base import ImporterError
from connmap.importers.tools import make_connector
from connmap.model.connector import Assistant, Connector
from connmap.model.trust import KIND_PROFILES, canonical_kind


class MCPImporter:
    format_name = "mcp"

    def matches(self, data: Mapping[str, Any]) -> bool:
        return "mcpServers" in data

    def parse(self, data: Mapping[str, Any]) -> Assistant:
        servers = data.get("mcpServers")
        if not isinstance(servers, Mapping) or not servers:
            raise ImporterError("mcp config has no mcpServers")

        connectors: list[Connector] = []
        for server_id, spec in servers.items():
            if not isinstance(server_id, str) or not server_id:
                raise ImporterError(f"mcp server has a non-string name: {server_id!r}")
            spec = spec if isinstance(spec, Mapping) else {}
            hint = spec.get("connmap")
            hint = hint if isinstance(hint, Mapping) else {}
            raw_kind = str(hint.get("kind") or _infer_kind(server_id) or server_id)
            connectors.append(
                make_connector(
                    connector_id=server_id,
                    name=str(hint.get("label") or server_id),
                    raw_kind=raw_kind,
                    tools=_as_str_list(spec.get("tools")),
                    trusted=bool(hint.get("trusted", False)),
                    description=str(spec.get("description", "")),
                )
            )

        name = data.get("name")
        return Assistant(
            name=str(name) if isinstance(name, str) and name else "MCP assistant",
            connectors=tuple(connectors),
            source_format=self.format_name,
        )


def _infer_kind(server_id: str) -> str | None:
    """Guess a canonical kind from the server name, if it maps to a known one."""
    kind = canonical_kind(server_id)
    return kind if kind in KIND_PROFILES else None


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
