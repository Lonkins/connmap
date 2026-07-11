"""Policy generation: rules sever the detected flows and preserve the rest."""

from __future__ import annotations

from pathlib import Path

from connmap.engine import Analysis, analyze
from connmap.importers import load_config
from connmap.model.connector import Assistant, Connector
from connmap.model.graph import build_graph
from connmap.policy import PolicyAction, apply_policy, generate_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _analyze(name: str) -> tuple[Assistant, Analysis]:
    assistant = load_config(EXAMPLES / name)
    return assistant, analyze(build_graph(assistant))


def test_policy_severs_confused_deputy_and_preserves_rest() -> None:
    assistant, result = _analyze("openclaw-vulnerable.json")
    assert not result.clean

    policy = generate_policy(assistant, result)
    assert policy.rules  # non-empty
    assert policy.default is PolicyAction.ALLOW

    # Applying the policy and re-analysing yields a clean config.
    hardened = apply_policy(assistant, policy)
    assert analyze(build_graph(hardened)).clean


def test_policy_rule_targets_exfil_hop_with_approval() -> None:
    assistant, result = _analyze("openclaw-vulnerable.json")
    policy = generate_policy(assistant, result)
    by_hop = {(r.source, r.target): r for r in policy.rules}

    rule = by_hop[("files", "http")]
    assert rule.action is PolicyAction.REQUIRE_APPROVAL
    assert "CD-001" in rule.addresses
    assert "http" in rule.reason


def test_policy_denies_executor_and_converges_via_fixpoint() -> None:
    assistant, result = _analyze("mcp-vulnerable.json")
    policy = generate_policy(assistant, result)
    hops = {(r.source, r.target): r.action for r in policy.rules}

    # Direct escalation is denied...
    assert hops[("telegram", "shell")] is PolicyAction.DENY
    # ...and so is the alternate path the fixpoint discovered through the pivot.
    assert hops[("filesystem", "shell")] is PolicyAction.DENY

    assert analyze(build_graph(apply_policy(assistant, policy))).clean


def test_clean_config_yields_empty_policy() -> None:
    assistant, result = _analyze("openclaw-hardened.json")
    policy = generate_policy(assistant, result)
    assert policy.rules == ()
    assert "No dangerous flows" in policy.rationale


def test_latent_exfil_policy() -> None:
    assistant = Assistant(
        name="latent",
        connectors=(
            Connector(id="files", kind="files"),
            Connector(id="http", kind="http_out"),
        ),
    )
    result = analyze(build_graph(assistant))
    policy = generate_policy(assistant, result)
    assert any(r.source == "files" and r.target == "http" for r in policy.rules)
    assert analyze(build_graph(apply_policy(assistant, policy))).clean


def test_policy_to_dict_is_assistant_consumable() -> None:
    assistant, result = _analyze("openclaw-vulnerable.json")
    doc = generate_policy(assistant, result).to_dict()
    assert doc["connmap_policy_version"] == "1.0"
    assert doc["default"] == "allow"
    assert doc["rules"]
    rule = doc["rules"][0]
    assert set(rule) == {"from", "to", "action", "reason", "addresses"}
