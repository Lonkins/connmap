"""The trust-annotated data-flow graph.

A :class:`DataFlowGraph` wraps a ``networkx.DiGraph`` whose nodes are connectors
(coloured by trust role) and whose edges are possible data movements. The
wrapper keeps typed access on the outside so the ``networkx`` ``Any`` surface
stays contained to this module.
"""

from __future__ import annotations

from collections import Counter
from enum import StrEnum

import networkx as nx
from pydantic import BaseModel, ConfigDict

from connmap.model.connector import Assistant, Connector
from connmap.model.trust import SINK_CAPS, Capability, TrustRole


class EdgeKind(StrEnum):
    """Why an edge exists — used for narratives, colouring, and policy."""

    TRIGGER = "trigger"
    """An untrusted inbound message can trigger a sensitive read."""

    DATA = "data"
    """Data read from a sensitive source can flow into a sink."""

    DIRECT = "direct"
    """An untrusted inbound message can drive a sink directly."""

    ESCALATION = "escalation"
    """Reached via a universal executor (shell): read, write, or network."""

    FLOW = "flow"
    """A declared flow that does not match a more specific pattern."""


_EDGE_REASON: dict[EdgeKind, str] = {
    EdgeKind.TRIGGER: "an inbound message can trigger a read here",
    EdgeKind.DATA: "data read here can flow into this sink",
    EdgeKind.DIRECT: "an inbound message can drive this sink directly",
    EdgeKind.ESCALATION: "a shell/executor can reach this connector",
    EdgeKind.FLOW: "declared data flow",
}


class FlowEdge(BaseModel):
    """A directed edge: data can move from ``source`` to ``target``."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    kind: EdgeKind
    mediated: bool = False
    reason: str = ""


def infer_edge_kind(src: Connector, dst: Connector) -> EdgeKind:
    """Classify an edge from its endpoints' roles and capabilities."""
    if src.has(Capability.EXECUTE):
        return EdgeKind.ESCALATION
    if src.trust_role is TrustRole.UNTRUSTED_INBOUND and dst.has(Capability.READ_SENSITIVE):
        return EdgeKind.TRIGGER
    if src.has(Capability.READ_SENSITIVE) and dst.capabilities & SINK_CAPS:
        return EdgeKind.DATA
    if src.trust_role is TrustRole.UNTRUSTED_INBOUND and dst.capabilities & SINK_CAPS:
        return EdgeKind.DIRECT
    return EdgeKind.FLOW


def _synthesize_edges(assistant: Assistant) -> list[FlowEdge]:
    """Permissive default: the assistant may chain any enabled capability.

    Edges follow the natural pipeline order — inbound triggers reads, reads
    feed sinks, inbound can drive sinks directly — plus escalation edges out of
    any executor, which can read and reach the network on its own.
    """
    inbound = [c for c in assistant.connectors if c.trust_role is TrustRole.UNTRUSTED_INBOUND]
    sensitive = [c for c in assistant.connectors if c.has(Capability.READ_SENSITIVE)]
    sinks = [c for c in assistant.connectors if c.capabilities & SINK_CAPS]
    executors = [c for c in assistant.connectors if c.has(Capability.EXECUTE)]

    seen: set[tuple[str, str]] = set()
    edges: list[FlowEdge] = []

    def add(src: Connector, dst: Connector) -> None:
        if src.id == dst.id or (src.id, dst.id) in seen:
            return
        seen.add((src.id, dst.id))
        kind = infer_edge_kind(src, dst)
        edges.append(FlowEdge(source=src.id, target=dst.id, kind=kind, reason=_EDGE_REASON[kind]))

    for i in inbound:
        for s in sensitive:
            add(i, s)
        for k in sinks:
            add(i, k)
    for s in sensitive:
        for k in sinks:
            add(s, k)
    for x in executors:
        for s in sensitive:
            add(x, s)
        for k in sinks:
            add(x, k)
    return edges


def _declared_edges(assistant: Assistant) -> list[FlowEdge]:
    """Closed-world: only the flows the config explicitly declares."""
    edges: list[FlowEdge] = []
    for route in assistant.routes:
        src = assistant.connector(route.source)
        dst = assistant.connector(route.target)
        kind = infer_edge_kind(src, dst)
        edges.append(
            FlowEdge(
                source=route.source,
                target=route.target,
                kind=kind,
                mediated=route.mediated,
                reason=_EDGE_REASON[kind],
            )
        )
    return edges


class DataFlowGraph:
    """Typed wrapper over the connector data-flow ``DiGraph``."""

    def __init__(self, assistant: Assistant, edges: list[FlowEdge]) -> None:
        self.assistant = assistant
        self.connectors: dict[str, Connector] = {c.id: c for c in assistant.connectors}
        self.edges: tuple[FlowEdge, ...] = tuple(edges)

        graph: nx.DiGraph = nx.DiGraph()
        for c in assistant.connectors:
            graph.add_node(
                c.id,
                role=c.trust_role,
                name=c.name,
                kind=c.kind,
            )
        for e in self.edges:
            graph.add_edge(
                e.source,
                e.target,
                kind=e.kind,
                mediated=e.mediated,
                reason=e.reason,
            )
        self._graph = graph

    @property
    def nx(self) -> nx.DiGraph:
        """The underlying directed graph (for path queries)."""
        return self._graph

    def node_ids(self) -> tuple[str, ...]:
        return tuple(self.connectors)

    def connector(self, connector_id: str) -> Connector:
        return self.connectors[connector_id]

    def role_of(self, connector_id: str) -> TrustRole:
        return self.connectors[connector_id].trust_role

    def successors(self, connector_id: str) -> tuple[str, ...]:
        return tuple(self._graph.successors(connector_id))

    def edge(self, source: str, target: str) -> FlowEdge:
        for e in self.edges:
            if e.source == source and e.target == target:
                return e
        raise KeyError((source, target))

    def role_counts(self) -> dict[TrustRole, int]:
        counts = Counter(c.trust_role for c in self.assistant.connectors)
        return {role: counts.get(role, 0) for role in TrustRole}


def build_graph(assistant: Assistant) -> DataFlowGraph:
    """Build the trust-annotated data-flow graph for an assistant.

    Uses the declared routes when present (closed-world allow-list), otherwise
    the permissive default (the assistant may chain any enabled capability).
    """
    edges = _declared_edges(assistant) if assistant.routes else _synthesize_edges(assistant)
    return DataFlowGraph(assistant, edges)
