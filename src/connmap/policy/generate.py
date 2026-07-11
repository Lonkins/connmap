"""Generate a least-privilege policy that severs the detected attack paths.

Strategy: for each finding, target the *critical hop* — the edge into the sink.
Deny it when the sink is an executor or payment rail (untrusted input has no
business reaching those), otherwise require human approval (which preserves the
intended use while breaking silent attacker exfil). Applying the policy can
re-open an alternate path through a different pivot, so the generator iterates
to a fixpoint: it re-analyses the hardened config and adds hops until clean.
"""

from __future__ import annotations

from connmap.engine import Analysis, Finding, analyze
from connmap.model.connector import Assistant, Route
from connmap.model.graph import build_graph
from connmap.model.trust import Capability
from connmap.policy.models import Policy, PolicyAction, PolicyRule

_Hop = tuple[str, str]
_MAX_ROUNDS = 64  # safety bound; convergence is monotone (hops only grow)


def generate_policy(assistant: Assistant, analysis: Analysis) -> Policy:
    """Build a policy whose rules sever every path in ``analysis``.

    ``analysis`` must be the result of analysing ``assistant``.
    """
    hops: dict[_Hop, PolicyAction] = {}
    base_graph = build_graph(assistant)
    current = analysis

    rounds = 0
    while not current.clean and rounds < _MAX_ROUNDS:
        rounds += 1
        added = False
        for finding in current.findings:
            hop = _critical_hop(finding)
            if hop not in hops:
                hops[hop] = _action_for(base_graph.connector(finding.sink).capabilities)
                added = True
        if not added:
            break  # no progress possible; stop rather than loop forever
        current = analyze(build_graph(_apply_hops(assistant, hops)))

    rules = _build_rules(hops, analysis)
    return Policy(
        assistant=assistant.name,
        rules=rules,
        rationale=_rationale(analysis, rules),
    )


def apply_policy(assistant: Assistant, policy: Policy) -> Assistant:
    """Return a hardened assistant with the policy baked into explicit routing.

    Denied hops are removed; require-approval hops become mediated. The result
    is a closed-world config: re-analysing it reflects the policy's effect.
    """
    hops = {(rule.source, rule.target): rule.action for rule in policy.rules}
    return _apply_hops(assistant, hops)


def _apply_hops(assistant: Assistant, hops: dict[_Hop, PolicyAction]) -> Assistant:
    graph = build_graph(assistant)
    routes: list[Route] = []
    for edge in graph.edges:
        action = hops.get((edge.source, edge.target), PolicyAction.ALLOW)
        if action is PolicyAction.DENY:
            continue  # drop the edge entirely
        mediated = edge.mediated or action is PolicyAction.REQUIRE_APPROVAL
        routes.append(Route(source=edge.source, target=edge.target, mediated=mediated))
    return assistant.model_copy(update={"routes": tuple(routes)})


def _critical_hop(finding: Finding) -> _Hop:
    chain = finding.chain
    if len(chain) < 2:
        return chain[0], chain[0]
    return chain[-2], chain[-1]


def _action_for(sink_capabilities: frozenset[Capability]) -> PolicyAction:
    if sink_capabilities & {Capability.EXECUTE, Capability.PAYMENT}:
        return PolicyAction.DENY
    return PolicyAction.REQUIRE_APPROVAL


def _build_rules(hops: dict[_Hop, PolicyAction], analysis: Analysis) -> tuple[PolicyRule, ...]:
    rules: list[PolicyRule] = []
    for (source, target), action in sorted(hops.items()):
        # A hop guards the sink it delivers into, so it addresses every finding
        # whose sink is that target.
        addresses = tuple(sorted(f.code for f in analysis.findings if f.sink == target))
        rules.append(
            PolicyRule(
                source=source,
                target=target,
                action=action,
                reason=_reason(source, target, action),
                addresses=addresses,
            )
        )
    return tuple(rules)


def _reason(source: str, target: str, action: PolicyAction) -> str:
    if action is PolicyAction.DENY:
        return (
            f"Deny the {source} → {target} data flow: untrusted-triggered input must not "
            f"reach {target} (an executor or payment rail)."
        )
    return (
        f"Require human approval on the {source} → {target} hop: breaks silent exfiltration "
        f"into {target} while still allowing approved, intentional use."
    )


def _rationale(analysis: Analysis, rules: tuple[PolicyRule, ...]) -> str:
    denied = sum(1 for r in rules if r.action is PolicyAction.DENY)
    gated = sum(1 for r in rules if r.action is PolicyAction.REQUIRE_APPROVAL)
    n_findings = len(analysis.findings)
    if not rules:
        return "No dangerous flows detected; no policy rules are required."
    return (
        f"connmap generated {len(rules)} least-privilege rule(s) that sever all {n_findings} "
        f"detected attack path(s): {denied} denied outright, {gated} gated behind human "
        f"approval. Every other data flow remains allowed, so intended behaviour is preserved."
    )
