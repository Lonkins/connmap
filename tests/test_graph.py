"""Graph construction: permissive default, closed-world routes, invariants."""

from __future__ import annotations

import networkx as nx
import pytest

from connmap.model.connector import Assistant, Connector, Route
from connmap.model.graph import EdgeKind, build_graph
from connmap.model.trust import TrustRole


def _confused_deputy_config() -> Assistant:
    return Assistant(
        name="test",
        connectors=(
            Connector(id="wa", kind="whatsapp"),
            Connector(id="files", kind="files"),
            Connector(id="http", kind="http_out"),
        ),
    )


def test_permissive_default_builds_confused_deputy_path() -> None:
    graph = build_graph(_confused_deputy_config())
    edge_pairs = {(e.source, e.target): e.kind for e in graph.edges}

    assert edge_pairs[("wa", "files")] is EdgeKind.TRIGGER
    assert edge_pairs[("files", "http")] is EdgeKind.DATA
    assert edge_pairs[("wa", "http")] is EdgeKind.DIRECT
    # The confused-deputy chain is reachable in the underlying graph.
    assert nx.has_path(graph.nx, "wa", "http")
    assert ["wa", "files", "http"] in list(nx.all_simple_paths(graph.nx, "wa", "http"))


def test_no_self_loops_and_valid_endpoints() -> None:
    graph = build_graph(_confused_deputy_config())
    nodes = set(graph.node_ids())
    for e in graph.edges:
        assert e.source != e.target
        assert e.source in nodes and e.target in nodes


def test_build_is_deterministic() -> None:
    config = _confused_deputy_config()
    assert build_graph(config).edges == build_graph(config).edges


def test_closed_world_uses_only_declared_routes() -> None:
    config = Assistant(
        name="hardened",
        connectors=(
            Connector(id="wa", kind="whatsapp"),
            Connector(id="files", kind="files"),
            Connector(id="http", kind="http_out"),
        ),
        # Declare only the benign hop; omit files -> http.
        routes=(Route(source="wa", target="files"),),
    )
    graph = build_graph(config)
    assert [(e.source, e.target) for e in graph.edges] == [("wa", "files")]
    assert not nx.has_path(graph.nx, "files", "http")


def test_mediated_route_is_marked() -> None:
    config = Assistant(
        name="mediated",
        connectors=(
            Connector(id="files", kind="files"),
            Connector(id="http", kind="http_out"),
        ),
        routes=(Route(source="files", target="http", mediated=True),),
    )
    edge = build_graph(config).edge("files", "http")
    assert edge.mediated is True


def test_escalation_edges_from_executor() -> None:
    config = Assistant(
        name="shelly",
        connectors=(
            Connector(id="wa", kind="whatsapp"),
            Connector(id="files", kind="files"),
            Connector(id="sh", kind="shell"),
        ),
    )
    graph = build_graph(config)
    kinds = {(e.source, e.target): e.kind for e in graph.edges}
    # Shell can reach the sensitive source and is itself a sink for inbound.
    assert kinds[("sh", "files")] is EdgeKind.ESCALATION
    assert kinds[("wa", "sh")] is EdgeKind.DIRECT


def test_graph_accessors_and_flow_edge() -> None:
    # Two neutral connectors with a declared route -> a generic FLOW edge.
    config = Assistant(
        name="neutral",
        connectors=(
            Connector(id="a", kind="mystery"),
            Connector(id="b", kind="another_mystery"),
        ),
        routes=(Route(source="a", target="b"),),
    )
    graph = build_graph(config)
    assert graph.role_of("a") is TrustRole.NEUTRAL
    assert graph.connector("b").id == "b"
    assert graph.successors("a") == ("b",)
    assert graph.edge("a", "b").kind is EdgeKind.FLOW
    with pytest.raises(KeyError):
        graph.edge("b", "a")


def test_role_counts_cover_all_connectors() -> None:
    graph = build_graph(_confused_deputy_config())
    counts = graph.role_counts()
    assert counts[TrustRole.UNTRUSTED_INBOUND] == 1
    assert counts[TrustRole.SENSITIVE_SOURCE] == 1
    assert counts[TrustRole.ACTION_OR_EXFIL] == 1
    assert sum(counts.values()) == len(graph.node_ids())
