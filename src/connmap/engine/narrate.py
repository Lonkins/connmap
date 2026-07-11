"""Turn a detected attack chain into a concrete attacker narrative and a fix.

Narratives name the exact connector chain so a reader can act on them without
re-deriving the analysis.
"""

from __future__ import annotations

from collections.abc import Sequence

from connmap.model.graph import DataFlowGraph


def render_chain(path: Sequence[str]) -> str:
    return " → ".join(path)


def _name(graph: DataFlowGraph, connector_id: str) -> str:
    return graph.connector(connector_id).name


def _kind(graph: DataFlowGraph, connector_id: str) -> str:
    return graph.connector(connector_id).kind


def _join_names(graph: DataFlowGraph, ids: Sequence[str]) -> str:
    names = [_name(graph, i) for i in ids]
    if not names:
        return "sensitive data"
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + f" and {names[-1]}"


def confused_deputy_narrative(
    graph: DataFlowGraph, path: Sequence[str], source: str, sink: str, pivots: Sequence[str]
) -> str:
    chain = render_chain(path)
    reads = _join_names(graph, pivots)
    if sink == source:
        delivery = (
            f"replies to the attacker through {_name(graph, sink)} "
            f"({_kind(graph, sink)}) with your private data"
        )
    else:
        delivery = f"hands the data to {_name(graph, sink)} ({_kind(graph, sink)})"
    return (
        f"An attacker plants a crafted message in {_name(graph, source)} "
        f"(an untrusted {_kind(graph, source)} channel). Acting as a confused deputy, "
        f"the assistant follows the embedded instruction: it reads {reads} and {delivery}. "
        f"Every hop on {chain} is unmediated, so attacker-controlled input can steer a "
        f"sensitive read straight into an outbound action."
    )


def privilege_escalation_narrative(
    graph: DataFlowGraph, path: Sequence[str], source: str, sink: str
) -> str:
    chain = render_chain(path)
    return (
        f"An attacker plants a crafted message in {_name(graph, source)} "
        f"(an untrusted {_kind(graph, source)} channel). Because the assistant can reach "
        f"{_name(graph, sink)}, an executor ({_kind(graph, sink)}), over the unmediated path "
        f"{chain}, the attacker can make it run arbitrary commands — escalating from a chat "
        f"message to code execution with the assistant's full privileges."
    )


def latent_exfil_narrative(
    graph: DataFlowGraph, path: Sequence[str], source: str, sink: str
) -> str:
    chain = render_chain(path)
    return (
        f"{_name(graph, source)} holds sensitive data and can reach {_name(graph, sink)} "
        f"({_kind(graph, sink)}) over the unmediated path {chain} with nothing in between. "
        f"No untrusted entry point is wired to it today, but this is a latent egress route: "
        f"any future inbound wiring — or a compromised upstream — turns it into a "
        f"confused-deputy exfiltration."
    )


def _critical_hop(path: Sequence[str]) -> tuple[str, str]:
    """The last hop of the chain — the edge whose removal severs the attack."""
    if len(path) < 2:
        return path[0], path[0]
    return path[-2], path[-1]


def confused_deputy_recommendation(
    graph: DataFlowGraph, path: Sequence[str], source: str, sink: str
) -> str:
    hop_src, hop_dst = _critical_hop(path)
    return (
        f"Break the final hop {hop_src} → {hop_dst}: require human approval on it, or "
        f"deny {sink} for any flow that originated at the untrusted source {source}. "
        f"connmap's generated policy applies this automatically."
    )


def privilege_escalation_recommendation(source: str, sink: str) -> str:
    return (
        f"Do not let untrusted input from {source} reach the executor {sink}: require "
        f"approval before {source}-triggered flows can invoke {sink}, or disable {sink} for "
        f"untrusted-triggered actions entirely."
    )


def latent_exfil_recommendation(path: Sequence[str], sink: str) -> str:
    hop_src, hop_dst = _critical_hop(path)
    return (
        f"Require approval or deny on the {hop_src} → {hop_dst} hop before any inbound "
        f"connector is wired to this sensitive source."
    )
