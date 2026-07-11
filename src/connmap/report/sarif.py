"""SARIF 2.1.0 report so findings ingest into code-scanning dashboards."""

from __future__ import annotations

import json
from typing import Any

from connmap import __version__
from connmap.engine import Analysis, Finding, Severity, ThreatKind
from connmap.engine.findings import THREAT_TITLE

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_HELP_URI = "https://github.com/Lonkins/connmap"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub code scanning reads this 0-10 number to rank severity.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}

_RULE_HELP: dict[ThreatKind, str] = {
    ThreatKind.CONFUSED_DEPUTY: (
        "An untrusted inbound connector can steer a sensitive read into an outbound "
        "action over an unmediated path."
    ),
    ThreatKind.PRIVILEGE_ESCALATION: (
        "An untrusted inbound connector can reach an executor, turning a message into "
        "code execution."
    ),
    ThreatKind.UNMEDIATED_EXFIL: (
        "A sensitive source can reach an exfil sink with no mediation: a latent egress route."
    ),
}


def _rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for kind in ThreatKind:
        rules.append(
            {
                "id": kind.value,
                "name": _pascal(kind.value),
                "shortDescription": {"text": THREAT_TITLE[kind]},
                "fullDescription": {"text": _RULE_HELP[kind]},
                "helpUri": _HELP_URI,
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "ai-agents", "data-flow"]},
            }
        )
    return rules


def _result(finding: Finding, config_uri: str) -> dict[str, Any]:
    return {
        "ruleId": finding.kind.value,
        "level": _LEVEL[finding.severity],
        "message": {"text": f"[{finding.code}] {finding.narrative}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": config_uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"connmapChain": "/".join(finding.chain)},
        "properties": {
            "code": finding.code,
            "severity": finding.severity.value,
            "chain": list(finding.chain),
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def build_sarif_report(analysis: Analysis, config_uri: str) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document for the analysis."""
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "connmap",
                        "informationUri": _HELP_URI,
                        "version": __version__,
                        "rules": _rules(),
                    }
                },
                "results": [_result(f, config_uri) for f in analysis.sorted_by_severity()],
            }
        ],
    }


def dumps_sarif_report(analysis: Analysis, config_uri: str) -> str:
    return json.dumps(build_sarif_report(analysis, config_uri), indent=2)


def _pascal(snake: str) -> str:
    return "".join(part.capitalize() for part in snake.split("_"))
