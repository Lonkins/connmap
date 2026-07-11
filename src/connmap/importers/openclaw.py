"""Importer for the OpenClaw local-assistant config schema.

OpenClaw configs list ``connectors`` (each with a ``type`` and the ``tools`` it
exposes) and an optional ``routing`` block. Routing ``mode: "explicit"`` turns
the ``rules`` into a closed-world allow-list; anything else (or no routing) is
the permissive default, where the assistant may chain any enabled tool.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from connmap.importers.base import ImporterError
from connmap.importers.tools import make_connector
from connmap.model.connector import Assistant, Connector, Route


class OpenClawImporter:
    format_name = "openclaw"

    def matches(self, data: Mapping[str, Any]) -> bool:
        return "openclaw_version" in data or "connectors" in data

    def parse(self, data: Mapping[str, Any]) -> Assistant:
        raw_connectors = data.get("connectors")
        if not isinstance(raw_connectors, list) or not raw_connectors:
            raise ImporterError("openclaw config has no connectors")

        connectors: list[Connector] = []
        for raw in raw_connectors:
            if not isinstance(raw, Mapping):
                raise ImporterError(f"connector entry is not an object: {raw!r}")
            if raw.get("enabled", True) is False:
                continue
            connector_id = raw.get("id")
            if not connector_id or not isinstance(connector_id, str):
                raise ImporterError(f"connector missing a string id: {dict(raw)!r}")
            raw_kind = raw.get("type") or raw.get("kind") or connector_id
            connectors.append(
                make_connector(
                    connector_id=connector_id,
                    name=str(raw.get("label") or raw.get("name") or connector_id),
                    raw_kind=str(raw_kind),
                    tools=_as_str_list(raw.get("tools")),
                    trusted=bool(raw.get("trusted", False)),
                    description=str(raw.get("description", "")),
                )
            )

        if not connectors:
            raise ImporterError("openclaw config has no enabled connectors")

        routes = _parse_routes(data.get("routing"))
        assistant_name = _assistant_name(data)
        return Assistant(
            name=assistant_name,
            connectors=tuple(connectors),
            routes=routes,
            source_format=self.format_name,
        )


def _assistant_name(data: Mapping[str, Any]) -> str:
    block = data.get("assistant")
    if isinstance(block, Mapping):
        name = block.get("name")
        if isinstance(name, str) and name:
            return name
    return "OpenClaw assistant"


def _parse_routes(routing: Any) -> tuple[Route, ...]:
    if not isinstance(routing, Mapping) or routing.get("mode") != "explicit":
        return ()
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return ()
    routes: list[Route] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise ImporterError(f"routing rule is not an object: {rule!r}")
        source = rule.get("from")
        target = rule.get("to")
        if not isinstance(source, str) or not isinstance(target, str):
            raise ImporterError(f"routing rule needs string 'from' and 'to': {dict(rule)!r}")
        routes.append(
            Route(source=source, target=target, mediated=bool(rule.get("mediated", False)))
        )
    return tuple(routes)


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
