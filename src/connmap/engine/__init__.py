"""The connmap threat engine: detect confused-deputy, escalation, exfil paths."""

from __future__ import annotations

from connmap.engine.detect import analyze
from connmap.engine.findings import (
    SEVERITY_RANK,
    THREAT_PREFIX,
    THREAT_TITLE,
    Analysis,
    Finding,
    Severity,
    ThreatKind,
)

__all__ = [
    "SEVERITY_RANK",
    "THREAT_PREFIX",
    "THREAT_TITLE",
    "Analysis",
    "Finding",
    "Severity",
    "ThreatKind",
    "analyze",
]
