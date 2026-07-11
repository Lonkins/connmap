"""Least-privilege policy generation."""

from __future__ import annotations

from connmap.policy.generate import apply_policy, generate_policy
from connmap.policy.models import Policy, PolicyAction, PolicyRule

__all__ = [
    "Policy",
    "PolicyAction",
    "PolicyRule",
    "apply_policy",
    "generate_policy",
]
