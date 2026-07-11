"""Least-privilege policy models.

A :class:`Policy` is an allow/deny (and require-approval) statement over
connector-to-connector data-flow hops, in a shape an assistant can consume:
``default: allow`` plus a small set of rules that break the dangerous flows.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyRule(BaseModel):
    """A rule targeting one data-flow hop (``source -> target``)."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    action: PolicyAction
    reason: str
    addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source,
            "to": self.target,
            "action": self.action.value,
            "reason": self.reason,
            "addresses": list(self.addresses),
        }


class Policy(BaseModel):
    """A default-allow policy with rules that sever the detected attack paths."""

    model_config = ConfigDict(frozen=True)

    version: str = "1.0"
    assistant: str
    default: PolicyAction = PolicyAction.ALLOW
    rules: tuple[PolicyRule, ...] = ()
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Render the assistant-consumable policy document."""
        return {
            "connmap_policy_version": self.version,
            "assistant": self.assistant,
            "default": self.default.value,
            "rules": [rule.to_dict() for rule in self.rules],
            "rationale": self.rationale,
        }
