"""connmap domain model: trust taxonomy, connectors, and the data-flow graph."""

from __future__ import annotations

from connmap.model.connector import Assistant, Connector, Route
from connmap.model.graph import (
    DataFlowGraph,
    EdgeKind,
    FlowEdge,
    build_graph,
    infer_edge_kind,
)
from connmap.model.trust import (
    EXECUTE_CAPS,
    EXFIL_CAPS,
    INBOUND_CAPS,
    KIND_PROFILES,
    SENSITIVE_CAPS,
    SINK_CAPS,
    Capability,
    TrustRole,
    canonical_kind,
    classify_role,
    default_capabilities_for,
)

__all__ = [
    "EXECUTE_CAPS",
    "EXFIL_CAPS",
    "INBOUND_CAPS",
    "KIND_PROFILES",
    "SENSITIVE_CAPS",
    "SINK_CAPS",
    "Assistant",
    "Capability",
    "Connector",
    "DataFlowGraph",
    "EdgeKind",
    "FlowEdge",
    "Route",
    "TrustRole",
    "build_graph",
    "canonical_kind",
    "classify_role",
    "default_capabilities_for",
    "infer_edge_kind",
]
