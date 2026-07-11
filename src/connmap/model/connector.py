"""Validated internal representation of an assistant and its connectors.

This is the boundary type: importers produce an :class:`Assistant`, and every
downstream stage (graph, engine, policy, reporters) consumes it. Validation
here means the rest of the code can treat the data as total and well-formed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from connmap.model.trust import (
    Capability,
    TrustRole,
    canonical_kind,
    classify_role,
    default_capabilities_for,
)


class Connector(BaseModel):
    """A single integration the assistant is wired to.

    ``capabilities`` and ``trust_role`` are derived from ``kind`` when not given
    explicitly, so importers can stay thin. Marking a connector ``trusted``
    suppresses its untrusted-inbound classification.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(default="", min_length=1)  # validator fills from id when omitted
    kind: str = Field(min_length=1)
    # Derived from ``kind`` by the validator below when not given explicitly;
    # the defaults exist only so the constructor stays ergonomic and typed.
    capabilities: frozenset[Capability] = frozenset()
    trust_role: TrustRole = TrustRole.NEUTRAL
    trusted: bool = False
    description: str = ""

    @model_validator(mode="before")
    @classmethod
    def _fill_from_kind(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        data.setdefault("name", data.get("id"))
        raw_kind = data.get("kind")

        caps = data.get("capabilities")
        if caps is None:
            caps = default_capabilities_for(raw_kind)
        caps = frozenset(Capability(c) for c in caps)
        data["capabilities"] = caps

        trusted = bool(data.get("trusted", False))
        if data.get("trust_role") is None:
            data["trust_role"] = classify_role(caps, trusted=trusted)
        if isinstance(raw_kind, str):
            data["kind"] = canonical_kind(raw_kind)
        return data

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities


class Route(BaseModel):
    """A declared allowed data flow between two connectors.

    When an assistant provides explicit routes, connmap treats them as a
    closed-world allow-list (least-privilege wiring). ``mediated`` marks a hop
    that passes through a trust boundary — human approval, sanitisation — which
    breaks a confused-deputy chain.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    mediated: bool = False


class Assistant(BaseModel):
    """The whole imported configuration: connectors plus optional wiring.

    Empty ``routes`` means "permissive default" — the assistant may chain any
    enabled capability, which is how most personal assistants actually behave
    and exactly what makes confused-deputy attacks possible. Non-empty
    ``routes`` is a declared allow-list.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    connectors: tuple[Connector, ...]
    routes: tuple[Route, ...] = ()
    source_format: str = "unknown"

    @model_validator(mode="after")
    def _check_integrity(self) -> Assistant:
        ids = [c.id for c in self.connectors]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"duplicate connector ids: {sorted(duplicates)}")
        known = set(ids)
        for route in self.routes:
            missing = {route.source, route.target} - known
            if missing:
                raise ValueError(f"route references unknown connector(s): {sorted(missing)}")
            if route.source == route.target:
                raise ValueError(f"route is a self-loop on {route.source!r}")
        return self

    def connector(self, connector_id: str) -> Connector:
        for c in self.connectors:
            if c.id == connector_id:
                return c
        raise KeyError(connector_id)

    def by_role(self, role: TrustRole) -> tuple[Connector, ...]:
        return tuple(c for c in self.connectors if c.trust_role == role)
