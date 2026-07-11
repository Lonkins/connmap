"""Smoke tests for the CLI entry point and package metadata."""

from __future__ import annotations

from typer.testing import CliRunner

from connmap import __version__
from connmap.cli import app

runner = CliRunner()


def test_version_command_prints_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.stdout


def test_package_exposes_version() -> None:
    assert __version__
    assert isinstance(__version__, str)


def test_dunder_main_importable() -> None:
    import importlib

    module = importlib.import_module("connmap.__main__")
    assert module is not None
