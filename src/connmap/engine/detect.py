"""Threat detection rules over the trust-annotated data-flow graph.

Three rules, each producing findings with a concrete attacker chain:

* **Confused deputy** — untrusted inbound reaches a sensitive read whose data
  reaches an exfil sink, all unmediated.
* **Privilege escalation** — untrusted inbound reaches an executor (shell),
  turning a message into code execution.
* **Unmediated exfil** — a sensitive source can reach an exfil sink with no
  mediation and no inbound wired to it yet: a latent egress route.
"""

from __future__ import annotations

import networkx as nx

from connmap.engine import narrate
from connmap.engine.findings import (
    THREAT_PREFIX,
    THREAT_TITLE,
    Analysis,
    Finding,
    Severity,
    ThreatKind,
)
from connmap.engine.paths import shortest_path, shortest_path_through, unmediated_subgraph
from connmap.model.graph import DataFlowGraph
from connmap.model.trust import EXFIL_CAPS, Capability, TrustRole


def analyze(graph: DataFlowGraph) -> Analysis:
    """Run every detection rule and return a stable, coded Analysis."""
    sub = unmediated_subgraph(graph)
    findings: list[Finding] = []
    findings += _assign_codes(_confused_deputy(graph, sub))
    findings += _assign_codes(_privilege_escalation(graph, sub))
    findings += _assign_codes(_latent_exfil(graph, sub))
    return Analysis(
        assistant_name=graph.assistant.name,
        source_format=graph.assistant.source_format,
        findings=tuple(findings),
    )


def _inbound(graph: DataFlowGraph) -> list[str]:
    return [c.id for c in graph.assistant.connectors if c.trust_role is TrustRole.UNTRUSTED_INBOUND]


def _sensitive(graph: DataFlowGraph) -> list[str]:
    return [c.id for c in graph.assistant.connectors if c.has(Capability.READ_SENSITIVE)]


def _exfil_sinks(graph: DataFlowGraph) -> list[str]:
    return [c.id for c in graph.assistant.connectors if c.capabilities & EXFIL_CAPS]


def _executors(graph: DataFlowGraph) -> list[str]:
    return [c.id for c in graph.assistant.connectors if c.has(Capability.EXECUTE)]


def _confused_deputy(graph: DataFlowGraph, sub: nx.DiGraph) -> list[Finding]:
    sensitive = _sensitive(graph)
    sensitive_set = set(sensitive)
    findings: list[Finding] = []
    for source in _inbound(graph):
        for sink in _exfil_sinks(graph):
            path = shortest_path_through(sub, source, sink, sensitive)
            if path is None:
                continue
            pivots = tuple(n for n in path if n in sensitive_set)
            findings.append(
                Finding(
                    code="",
                    kind=ThreatKind.CONFUSED_DEPUTY,
                    severity=Severity.CRITICAL,
                    title=THREAT_TITLE[ThreatKind.CONFUSED_DEPUTY],
                    chain=tuple(path),
                    source=source,
                    sink=sink,
                    pivots=pivots,
                    narrative=narrate.confused_deputy_narrative(graph, path, source, sink, pivots),
                    recommendation=narrate.confused_deputy_recommendation(
                        graph, path, source, sink
                    ),
                )
            )
    return _sorted(findings)


def _privilege_escalation(graph: DataFlowGraph, sub: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    for source in _inbound(graph):
        for sink in _executors(graph):
            if sink == source:
                continue
            path = shortest_path(sub, source, sink)
            if path is None:
                continue
            findings.append(
                Finding(
                    code="",
                    kind=ThreatKind.PRIVILEGE_ESCALATION,
                    severity=Severity.CRITICAL,
                    title=THREAT_TITLE[ThreatKind.PRIVILEGE_ESCALATION],
                    chain=tuple(path),
                    source=source,
                    sink=sink,
                    pivots=(),
                    narrative=narrate.privilege_escalation_narrative(graph, path, source, sink),
                    recommendation=narrate.privilege_escalation_recommendation(source, sink),
                )
            )
    return _sorted(findings)


def _latent_exfil(graph: DataFlowGraph, sub: nx.DiGraph) -> list[Finding]:
    inbound = _inbound(graph)
    findings: list[Finding] = []
    for source in _sensitive(graph):
        if any(shortest_path(sub, i, source) is not None for i in inbound):
            continue  # reachable from an inbound source -> reported as a confused deputy
        for sink in _exfil_sinks(graph):
            if sink == source:
                continue
            path = shortest_path(sub, source, sink)
            if path is None:
                continue
            findings.append(
                Finding(
                    code="",
                    kind=ThreatKind.UNMEDIATED_EXFIL,
                    severity=Severity.HIGH,
                    title=THREAT_TITLE[ThreatKind.UNMEDIATED_EXFIL],
                    chain=tuple(path),
                    source=source,
                    sink=sink,
                    pivots=(source,),
                    narrative=narrate.latent_exfil_narrative(graph, path, source, sink),
                    recommendation=narrate.latent_exfil_recommendation(path, sink),
                )
            )
    return _sorted(findings)


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.chain, f.source, f.sink))


def _assign_codes(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for index, finding in enumerate(findings, start=1):
        prefix = THREAT_PREFIX[finding.kind]
        out.append(finding.model_copy(update={"code": f"{prefix}-{index:03d}"}))
    return out
