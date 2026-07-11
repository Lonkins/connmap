"""Finding and analysis result models produced by the threat engine."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class ThreatKind(StrEnum):
    CONFUSED_DEPUTY = "confused_deputy"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNMEDIATED_EXFIL = "unmediated_exfil"


THREAT_PREFIX: dict[ThreatKind, str] = {
    ThreatKind.CONFUSED_DEPUTY: "CD",
    ThreatKind.PRIVILEGE_ESCALATION: "PE",
    ThreatKind.UNMEDIATED_EXFIL: "EX",
}

THREAT_TITLE: dict[ThreatKind, str] = {
    ThreatKind.CONFUSED_DEPUTY: "Confused-deputy exfiltration path",
    ThreatKind.PRIVILEGE_ESCALATION: "Privilege escalation to an executor",
    ThreatKind.UNMEDIATED_EXFIL: "Unmediated data-egress route",
}


class Finding(BaseModel):
    """One detected threat: a concrete attacker chain over the connector graph."""

    model_config = ConfigDict(frozen=True)

    code: str
    kind: ThreatKind
    severity: Severity
    title: str
    chain: tuple[str, ...]
    source: str
    sink: str
    pivots: tuple[str, ...]
    narrative: str
    recommendation: str


class Analysis(BaseModel):
    """The full result of analysing one assistant configuration."""

    model_config = ConfigDict(frozen=True)

    assistant_name: str
    source_format: str
    findings: tuple[Finding, ...]

    @property
    def clean(self) -> bool:
        return not self.findings

    def severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def sorted_by_severity(self) -> tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: (SEVERITY_RANK[f.severity], f.code)))

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])
