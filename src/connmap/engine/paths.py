"""Path helpers over the unmediated slice of the data-flow graph.

A mediated edge (human approval, sanitisation) breaks an attack chain, so the
engine reasons over the subgraph of *unmediated* edges only.
"""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx

from connmap.model.graph import DataFlowGraph


def unmediated_subgraph(graph: DataFlowGraph) -> nx.DiGraph:
    """Return a DiGraph containing only the unmediated edges."""
    sub: nx.DiGraph = nx.DiGraph()
    sub.add_nodes_from(graph.node_ids())
    for edge in graph.edges:
        if not edge.mediated:
            sub.add_edge(edge.source, edge.target)
    return sub


def shortest_path(sub: nx.DiGraph, source: str, target: str) -> list[str] | None:
    """Shortest directed path, or None if unreachable."""
    if not sub.has_node(source) or not sub.has_node(target):
        return None
    if not nx.has_path(sub, source, target):
        return None
    path: list[str] = nx.shortest_path(sub, source, target)
    return path


def shortest_path_through(
    sub: nx.DiGraph, source: str, target: str, via: Iterable[str]
) -> list[str] | None:
    """Shortest ``source -> target`` path passing through any node in ``via``.

    The via-node must be a genuine intermediate (not the source or target
    themselves), so the returned chain always demonstrates the pivot.
    """
    best: list[str] | None = None
    for pivot in via:
        if pivot in (source, target):
            continue
        left = shortest_path(sub, source, pivot)
        right = shortest_path(sub, pivot, target)
        if left is None or right is None:
            continue
        candidate = left + right[1:]
        if best is None or len(candidate) < len(best):
            best = candidate
    return best
