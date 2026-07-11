"""Connector / Assistant model derivation and boundary validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from connmap.model.connector import Assistant, Connector, Route
from connmap.model.trust import Capability, TrustRole


def test_connector_derives_from_kind() -> None:
    c = Connector(id="files", kind="filesystem")
    assert c.kind == "files"  # alias canonicalised
    assert c.name == "files"  # defaults to id
    assert Capability.READ_SENSITIVE in c.capabilities
    assert c.trust_role is TrustRole.SENSITIVE_SOURCE


def test_explicit_role_and_caps_override() -> None:
    c = Connector(
        id="x",
        name="Custom",
        kind="unknown_thing",
        capabilities=frozenset({Capability.NETWORK_OUT}),
        trust_role=TrustRole.NEUTRAL,
    )
    assert c.trust_role is TrustRole.NEUTRAL
    assert c.has(Capability.NETWORK_OUT)


def test_trusted_channel_not_inbound() -> None:
    c = Connector(id="wa", kind="whatsapp", trusted=True)
    assert c.trust_role is not TrustRole.UNTRUSTED_INBOUND


def test_unknown_kind_is_neutral() -> None:
    c = Connector(id="mystery", kind="quantum_widget")
    assert c.capabilities == frozenset()
    assert c.trust_role is TrustRole.NEUTRAL


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        Connector(id="x", kind="files", surprise="boom")  # type: ignore[call-arg]


def test_duplicate_ids_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate connector ids"):
        Assistant(
            name="a",
            connectors=(
                Connector(id="dup", kind="files"),
                Connector(id="dup", kind="shell"),
            ),
        )


def test_route_unknown_endpoint_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown connector"):
        Assistant(
            name="a",
            connectors=(Connector(id="files", kind="files"),),
            routes=(Route(source="files", target="ghost"),),
        )


def test_route_self_loop_rejected() -> None:
    with pytest.raises(ValidationError, match="self-loop"):
        Assistant(
            name="a",
            connectors=(Connector(id="files", kind="files"),),
            routes=(Route(source="files", target="files"),),
        )


def test_assistant_helpers() -> None:
    a = Assistant(
        name="a",
        connectors=(
            Connector(id="wa", kind="whatsapp"),
            Connector(id="files", kind="files"),
        ),
    )
    assert a.connector("wa").kind == "whatsapp"
    assert a.by_role(TrustRole.SENSITIVE_SOURCE) == (a.connector("files"),)
    with pytest.raises(KeyError):
        a.connector("nope")
