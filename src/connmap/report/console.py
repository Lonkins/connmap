"""Rich console rendering of an analysis."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from connmap.engine import Analysis, Severity
from connmap.model.graph import DataFlowGraph
from connmap.model.trust import TrustRole

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

_ROLE_STYLE: dict[TrustRole, str] = {
    TrustRole.UNTRUSTED_INBOUND: "red",
    TrustRole.SENSITIVE_SOURCE: "yellow",
    TrustRole.ACTION_OR_EXFIL: "magenta",
    TrustRole.NEUTRAL: "grey50",
}


def styled_chain(graph: DataFlowGraph, chain: Sequence[str]) -> Text:
    """Render a connector chain, each node coloured by its trust role."""
    text = Text()
    for index, node in enumerate(chain):
        if index:
            text.append("  →  ", style="grey50")
        style = _ROLE_STYLE.get(graph.role_of(node), "white")
        text.append(node, style=style)
    return text


def _role_legend(graph: DataFlowGraph) -> Text:
    counts = graph.role_counts()
    text = Text()
    for role in TrustRole:
        if counts[role] == 0:
            continue
        if text:
            text.append("   ")
        text.append("● ", style=_ROLE_STYLE[role])
        text.append(f"{counts[role]} {role.value}", style=_ROLE_STYLE[role])
    return text


def render_console(graph: DataFlowGraph, analysis: Analysis, console: Console) -> None:
    """Print a human-readable report to ``console``."""
    n_conn = len(graph.assistant.connectors)
    n_edge = len(graph.edges)
    n_find = len(analysis.findings)

    header = Text()
    header.append("connmap", style="bold")
    header.append(f"  ·  {n_conn} connectors  ·  {n_edge} edges  ·  ", style="grey62")
    header.append(f"{n_find} finding(s)", style="bold red" if n_find else "bold green")
    console.print(header)
    console.print(_role_legend(graph))
    console.print()

    if analysis.clean:
        console.print(
            Panel(
                Text("No dangerous flows detected. This configuration is clean.", style="green"),
                border_style="green",
                title="✓ clean",
                title_align="left",
            )
        )
        return

    for finding in analysis.sorted_by_severity():
        sev_style = _SEVERITY_STYLE[finding.severity]
        title = Text()
        title.append(finding.severity.value.upper(), style=sev_style)
        title.append(f"  {finding.code}  ", style="bold")
        title.append(finding.title, style="default")

        body = Text()
        body.append_text(styled_chain(graph, finding.chain))
        body.append("\n\n")
        body.append(finding.narrative)
        body.append("\n\n")
        body.append("Fix: ", style="bold green")
        body.append(finding.recommendation)

        console.print(Panel(body, title=title, title_align="left", border_style=sev_style))
