"""Reporters: console, JSON, and SARIF output for an analysis."""

from __future__ import annotations

from connmap.report.console import render_console, styled_chain
from connmap.report.json_report import build_json_report, dumps_json_report
from connmap.report.sarif import build_sarif_report, dumps_sarif_report

__all__ = [
    "build_json_report",
    "build_sarif_report",
    "dumps_json_report",
    "dumps_sarif_report",
    "render_console",
    "styled_chain",
]
