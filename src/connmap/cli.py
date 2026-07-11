"""connmap command-line interface.

``connmap analyze CONFIG`` builds the data-flow graph, runs the threat engine,
and reports findings (console + optional JSON/SARIF/policy artifacts).
``connmap policy CONFIG`` emits the least-privilege policy on its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from connmap import __version__
from connmap.engine import analyze as run_analysis
from connmap.importers import ImporterError, load_config
from connmap.model.connector import Assistant
from connmap.model.graph import build_graph
from connmap.policy import generate_policy
from connmap.render import render_html
from connmap.report import dumps_json_report, dumps_sarif_report, render_console

app = typer.Typer(
    name="connmap",
    help="Data-flow threat mapping for local AI-assistant connectors.",
    no_args_is_help=True,
    add_completion=False,
)

_out = Console()
_err = Console(stderr=True)

ImporterOpt = Annotated[
    str | None,
    typer.Option(
        "--importer", "-i", help="Config format: openclaw or mcp (auto-detected if omitted)."
    ),
]


@app.callback()
def main() -> None:
    """Data-flow threat mapping for local AI-assistant connectors."""


@app.command()
def version() -> None:
    """Print the connmap version."""
    typer.echo(__version__)


@app.command()
def analyze(
    config: Annotated[Path, typer.Argument(help="Path to the assistant config (.json).")],
    importer: ImporterOpt = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the JSON report to PATH.")
    ] = None,
    sarif_out: Annotated[
        Path | None, typer.Option("--sarif", help="Write the SARIF report to PATH.")
    ] = None,
    html_out: Annotated[
        Path | None,
        typer.Option("--html", help="Write the self-contained interactive HTML graph to PATH."),
    ] = None,
    policy_out: Annotated[
        Path | None, typer.Option("--policy", help="Write the least-privilege policy to PATH.")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress the console report.")
    ] = False,
    exit_zero: Annotated[
        bool, typer.Option("--exit-zero", help="Exit 0 even when findings are present.")
    ] = False,
) -> None:
    """Analyze a config: report confused-deputy, escalation, and exfil paths."""
    assistant = _load(config, importer)
    graph = build_graph(assistant)
    analysis = run_analysis(graph)
    policy = generate_policy(assistant, analysis)

    if json_out is not None:
        _write(json_out, dumps_json_report(graph, analysis, policy))
    if sarif_out is not None:
        _write(sarif_out, dumps_sarif_report(analysis, _config_uri(config)))
    if html_out is not None:
        _write(html_out, render_html(graph, analysis))
    if policy_out is not None:
        _write(policy_out, json.dumps(policy.to_dict(), indent=2))

    if not quiet:
        render_console(graph, analysis, _out)

    if analysis.findings and not exit_zero:
        raise typer.Exit(1)


@app.command()
def policy(
    config: Annotated[Path, typer.Argument(help="Path to the assistant config (.json).")],
    importer: ImporterOpt = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the policy to PATH (else stdout).")
    ] = None,
) -> None:
    """Generate a least-privilege policy that severs the dangerous flows."""
    assistant = _load(config, importer)
    analysis = run_analysis(build_graph(assistant))
    document = json.dumps(generate_policy(assistant, analysis).to_dict(), indent=2)
    if out is not None:
        _write(out, document)
    else:
        typer.echo(document)


def _load(config: Path, importer: str | None) -> Assistant:
    try:
        return load_config(config, fmt=importer)
    except ImporterError as exc:
        _err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _out.print(f"[grey62]wrote[/grey62] {path}")


def _config_uri(config: Path) -> str:
    try:
        return config.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return config.name


if __name__ == "__main__":  # pragma: no cover
    app()
