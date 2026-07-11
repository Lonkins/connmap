"""JSON report: the full analysis as a machine-readable document."""

from __future__ import annotations

import json
from typing import Any

from connmap import __version__
from connmap.engine import Analysis
from connmap.model.graph import DataFlowGraph
from connmap.policy import Policy


def build_json_report(
    graph: DataFlowGraph, analysis: Analysis, policy: Policy | None = None
) -> dict[str, Any]:
    """Assemble the analysis, graph, findings, and policy into one document."""
    connectors = graph.assistant.connectors
    return {
        "connmap_version": __version__,
        "assistant": analysis.assistant_name,
        "source_format": analysis.source_format,
        "summary": {
            "connectors": len(connectors),
            "edges": len(graph.edges),
            "findings": len(analysis.findings),
            "severity_counts": {
                sev.value: count for sev, count in analysis.severity_counts().items()
            },
            "roles": {role.value: count for role, count in graph.role_counts().items()},
        },
        "graph": {
            "nodes": [
                {
                    "id": c.id,
                    "name": c.name,
                    "kind": c.kind,
                    "role": c.trust_role.value,
                    "trusted": c.trusted,
                    "capabilities": sorted(cap.value for cap in c.capabilities),
                }
                for c in connectors
            ],
            "edges": [
                {
                    "from": e.source,
                    "to": e.target,
                    "kind": e.kind.value,
                    "mediated": e.mediated,
                    "reason": e.reason,
                }
                for e in graph.edges
            ],
        },
        "findings": [f.model_dump(mode="json") for f in analysis.sorted_by_severity()],
        "policy": policy.to_dict() if policy is not None else None,
    }


def dumps_json_report(
    graph: DataFlowGraph, analysis: Analysis, policy: Policy | None = None
) -> str:
    return json.dumps(build_json_report(graph, analysis, policy), indent=2)
