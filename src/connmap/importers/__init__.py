"""Config importers: turn a local assistant config into an ``Assistant``.

Ships importers for the OpenClaw schema and the generic MCP-integration schema.
Analysis is fully static — importers read a config document and never connect to
any integration.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from connmap.importers.base import Importer, ImporterError
from connmap.importers.mcp import MCPImporter
from connmap.importers.openclaw import OpenClawImporter
from connmap.model.connector import Assistant

# Registry, in detection order (most specific key first).
IMPORTERS: tuple[Importer, ...] = (MCPImporter(), OpenClawImporter())

__all__ = [
    "IMPORTERS",
    "Importer",
    "ImporterError",
    "MCPImporter",
    "OpenClawImporter",
    "available_formats",
    "get_importer",
    "load_config",
    "parse_document",
]


def available_formats() -> list[str]:
    return [imp.format_name for imp in IMPORTERS]


def get_importer(fmt: str) -> Importer:
    for imp in IMPORTERS:
        if imp.format_name == fmt:
            return imp
    raise ImporterError(f"unknown format {fmt!r}; choices: {available_formats()}")


def detect_importer(data: Mapping[str, Any]) -> Importer:
    for imp in IMPORTERS:
        if imp.matches(data):
            return imp
    raise ImporterError(
        f"could not detect config format; pass one of {available_formats()} explicitly"
    )


def parse_document(data: Mapping[str, Any], *, fmt: str | None = None) -> Assistant:
    """Parse an already-loaded config document into an Assistant."""
    importer = get_importer(fmt) if fmt else detect_importer(data)
    return importer.parse(data)


def load_config(path: str | Path, *, fmt: str | None = None) -> Assistant:
    """Read a JSON config file and import it into an Assistant.

    Auto-detects the format unless ``fmt`` is given. Analysis is static: this
    reads a local file and nothing else.
    """
    data = _read_json(path)
    return parse_document(data, fmt=fmt)


def _read_json(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise ImporterError(f"config not found: {p}")
    if p.suffix.lower() != ".json":
        raise ImporterError(f"unsupported config extension {p.suffix!r}; only .json is supported")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ImporterError(f"invalid JSON in {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ImporterError(f"config root must be a JSON object, got {type(data).__name__}")
    return data
