"""Render a self-contained, offline interactive HTML graph.

The output inlines d3 (vendored under ``assets/``), the stylesheet, the app
script, and the analysis data. It makes no external network calls, so it opens
straight from disk. The data payload is JSON with ``<``, ``>`` and ``&`` escaped
to their unicode forms, which is the standard safe way to embed JSON in an HTML
``<script>``; the app inserts all text via ``textContent``, never ``innerHTML``.
"""

from __future__ import annotations

import html as html_lib
import json
from importlib.resources import files
from typing import Any

from connmap.engine import Analysis
from connmap.model.graph import DataFlowGraph


def _asset(name: str) -> str:
    resource = files("connmap.render").joinpath("assets").joinpath(name)
    return resource.read_text(encoding="utf-8")


def build_graph_data(graph: DataFlowGraph, analysis: Analysis) -> dict[str, Any]:
    """Assemble the data blob the client script renders."""
    connectors = graph.assistant.connectors
    return {
        "assistant": analysis.assistant_name,
        "format": analysis.source_format,
        "counts": {
            "connectors": len(connectors),
            "edges": len(graph.edges),
            "findings": len(analysis.findings),
        },
        "roles": {role.value: count for role, count in graph.role_counts().items()},
        "nodes": [
            {"id": c.id, "name": c.name, "kind": c.kind, "role": c.trust_role.value}
            for c in connectors
        ],
        "links": [
            {
                "source": e.source,
                "target": e.target,
                "kind": e.kind.value,
                "mediated": e.mediated,
            }
            for e in graph.edges
        ],
        "findings": [
            {
                "code": f.code,
                "severity": f.severity.value,
                "kind": f.kind.value,
                "title": f.title,
                "chain": list(f.chain),
                "narrative": f.narrative,
                "recommendation": f.recommendation,
            }
            for f in analysis.sorted_by_severity()
        ],
    }


def _embed_json(data: dict[str, Any]) -> str:
    return json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _script_safe(source: str) -> str:
    # A literal </script anywhere in inlined code would close the block early.
    return source.replace("</script", "<\\/script")


def render_html(graph: DataFlowGraph, analysis: Analysis) -> str:
    """Return a complete, self-contained HTML document for the analysis."""
    payload = _embed_json(build_graph_data(graph, analysis))
    css = _asset("styles.css")
    d3 = _script_safe(_asset("d3.v7.min.js"))
    app_js = _script_safe(_asset("app.js"))
    title = html_lib.escape(f"connmap · {analysis.assistant_name}")

    return "".join(
        [
            "<!doctype html>\n",
            '<html lang="en">\n<head>\n',
            '<meta charset="utf-8">\n',
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
            f"<title>{title}</title>\n",
            f"<style>{css}</style>\n",
            "</head>\n<body>\n",
            '<div id="app"></div>\n',
            f"<script>{d3}</script>\n",
            f"<script>window.CONNMAP_DATA = {payload};</script>\n",
            f"<script>{app_js}</script>\n",
            "</body>\n</html>\n",
        ]
    )
