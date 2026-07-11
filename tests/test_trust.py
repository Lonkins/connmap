"""Trust taxonomy: classification, canonicalisation, capability profiles."""

from __future__ import annotations

from connmap.model.trust import (
    Capability,
    TrustRole,
    canonical_kind,
    classify_role,
    default_capabilities_for,
)

C = Capability


def test_inbound_dominates_classification() -> None:
    # A chat app both receives untrusted content and sends — inbound wins.
    assert classify_role(frozenset({C.RECEIVE_UNTRUSTED, C.SEND_MESSAGE})) is (
        TrustRole.UNTRUSTED_INBOUND
    )


def test_sink_before_sensitive() -> None:
    assert classify_role(frozenset({C.NETWORK_OUT})) is TrustRole.ACTION_OR_EXFIL
    assert classify_role(frozenset({C.EXECUTE})) is TrustRole.ACTION_OR_EXFIL
    assert classify_role(frozenset({C.PAYMENT})) is TrustRole.ACTION_OR_EXFIL


def test_sensitive_and_neutral() -> None:
    assert classify_role(frozenset({C.READ_SENSITIVE})) is TrustRole.SENSITIVE_SOURCE
    assert classify_role(frozenset({C.WRITE_SENSITIVE})) is TrustRole.SENSITIVE_SOURCE
    assert classify_role(frozenset()) is TrustRole.NEUTRAL


def test_trusted_suppresses_inbound() -> None:
    caps = frozenset({C.RECEIVE_UNTRUSTED, C.SEND_MESSAGE})
    # Trusted channel is no longer an entry point, but it can still send.
    assert classify_role(caps, trusted=True) is TrustRole.ACTION_OR_EXFIL
    # A trusted pure-inbound channel becomes neutral.
    assert classify_role(frozenset({C.RECEIVE_UNTRUSTED}), trusted=True) is TrustRole.NEUTRAL


def test_canonical_kind_resolves_aliases() -> None:
    assert canonical_kind("HTTP") == "http_out"
    assert canonical_kind(" Bash ") == "shell"
    assert canonical_kind("gmail") == "email"
    assert canonical_kind("filesystem") == "files"
    # Unknown kinds pass through unchanged.
    assert canonical_kind("quantum_widget") == "quantum_widget"


def test_default_capabilities() -> None:
    assert C.RECEIVE_UNTRUSTED in default_capabilities_for("whatsapp")
    assert C.READ_SENSITIVE in default_capabilities_for("files")
    assert default_capabilities_for("quantum_widget") == frozenset()
    assert default_capabilities_for(None) == frozenset()
