"""connmap command-line interface.

The full analyze / policy commands are wired up in later parts. For now the
app exposes ``version`` and serves as the package entry point.
"""

from __future__ import annotations

import typer

from connmap import __version__

app = typer.Typer(
    name="connmap",
    help="Data-flow threat mapping for local AI-assistant connectors.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """Data-flow threat mapping for local AI-assistant connectors."""
    # Present so Typer keeps subcommand mode even with a single command today;
    # later parts add `analyze` and `policy`.


@app.command()
def version() -> None:
    """Print the connmap version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
