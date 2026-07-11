"""The trust taxonomy: roles, capabilities, and how connectors are classified.

This module is the single source of truth for *what a connector can do* and
*how dangerous its position is*. Importers map raw config to canonical
connector ``kind``s; everything downstream reasons over the derived
:class:`Capability` set and :class:`TrustRole`.
"""

from __future__ import annotations

from enum import StrEnum


class TrustRole(StrEnum):
    """Where a connector sits in the trust landscape.

    The role is a *classification for colour and narrative*. Behaviour is
    driven by :class:`Capability`; a single connector can be an inbound entry
    point and still carry an outbound capability (a chat app both receives and
    sends). The role names the connector's dominant risk.
    """

    UNTRUSTED_INBOUND = "untrusted_inbound"
    """Ingests attacker-influenceable content: chat, SMS, email, web."""

    SENSITIVE_SOURCE = "sensitive_source"
    """Holds private data: files, contacts, calendar, notes."""

    ACTION_OR_EXFIL = "action_or_exfil"
    """Performs privileged actions or moves data out: shell, HTTP, payments."""

    NEUTRAL = "neutral"
    """No modelled risk (unknown kind, or an inbound channel marked trusted)."""


class Capability(StrEnum):
    """A concrete thing a connector can do. Roles are derived from these."""

    RECEIVE_UNTRUSTED = "receive_untrusted"
    """Accepts content an attacker can influence (a message, a web page)."""

    READ_SENSITIVE = "read_sensitive"
    """Reads private data the user would not want exfiltrated."""

    WRITE_SENSITIVE = "write_sensitive"
    """Modifies private data (tamper / integrity surface)."""

    SEND_MESSAGE = "send_message"
    """Sends a message to a channel or recipient (an exfil vector)."""

    NETWORK_OUT = "network_out"
    """Makes arbitrary outbound network requests (an exfil vector)."""

    EXECUTE = "execute"
    """Runs shell commands or code (a universal escalation primitive)."""

    PAYMENT = "payment"
    """Moves money (high-value action and exfil vector)."""


# --- Capability groupings the engine and graph builder reason over ----------

INBOUND_CAPS: frozenset[Capability] = frozenset({Capability.RECEIVE_UNTRUSTED})
"""Capabilities that make a connector an untrusted entry point."""

SENSITIVE_CAPS: frozenset[Capability] = frozenset(
    {Capability.READ_SENSITIVE, Capability.WRITE_SENSITIVE}
)
"""Capabilities that make a connector a sensitive-data holder."""

EXFIL_CAPS: frozenset[Capability] = frozenset(
    {Capability.SEND_MESSAGE, Capability.NETWORK_OUT, Capability.PAYMENT}
)
"""Capabilities through which data (or money) leaves the trust boundary."""

EXECUTE_CAPS: frozenset[Capability] = frozenset({Capability.EXECUTE})
"""The universal executor. Shell can read, write, and reach the network."""

SINK_CAPS: frozenset[Capability] = EXFIL_CAPS | EXECUTE_CAPS
"""Everything a confused deputy can be steered into performing."""


def classify_role(capabilities: frozenset[Capability], *, trusted: bool = False) -> TrustRole:
    """Deterministically assign a :class:`TrustRole` from capabilities.

    Priority: an untrusted entry point dominates (it is where attacker content
    enters), then an outbound/executor sink, then a sensitive source, else
    neutral. ``trusted=True`` suppresses the inbound classification for a
    channel the operator vouches for (e.g. a private, self-only webhook).
    """
    if not trusted and capabilities & INBOUND_CAPS:
        return TrustRole.UNTRUSTED_INBOUND
    if capabilities & SINK_CAPS:
        return TrustRole.ACTION_OR_EXFIL
    if capabilities & SENSITIVE_CAPS:
        return TrustRole.SENSITIVE_SOURCE
    return TrustRole.NEUTRAL


# --- Canonical connector kinds ---------------------------------------------
#
# The default capability profile for each canonical kind. Importers normalise
# provider-specific names to these via ``canonical_kind``. An unknown kind maps
# to no capabilities (a NEUTRAL node) rather than guessing.

KIND_PROFILES: dict[str, frozenset[Capability]] = {
    # untrusted inbound messaging / web
    "whatsapp": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "telegram": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "signal": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "sms": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "imessage": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "slack": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "email": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.SEND_MESSAGE}),
    "email_inbound": frozenset({Capability.RECEIVE_UNTRUSTED}),
    "web": frozenset({Capability.RECEIVE_UNTRUSTED}),
    "webhook": frozenset({Capability.RECEIVE_UNTRUSTED}),
    "rss": frozenset({Capability.RECEIVE_UNTRUSTED}),
    # sensitive sources
    "files": frozenset({Capability.READ_SENSITIVE, Capability.WRITE_SENSITIVE}),
    "contacts": frozenset({Capability.READ_SENSITIVE}),
    "calendar": frozenset({Capability.READ_SENSITIVE, Capability.WRITE_SENSITIVE}),
    "notes": frozenset({Capability.READ_SENSITIVE, Capability.WRITE_SENSITIVE}),
    "photos": frozenset({Capability.READ_SENSITIVE}),
    "health": frozenset({Capability.READ_SENSITIVE}),
    "location": frozenset({Capability.READ_SENSITIVE}),
    # actions / exfil
    "shell": frozenset({Capability.EXECUTE}),
    "code_interpreter": frozenset({Capability.EXECUTE}),
    "http_out": frozenset({Capability.NETWORK_OUT}),
    "email_send": frozenset({Capability.SEND_MESSAGE}),
    "send_message": frozenset({Capability.SEND_MESSAGE}),
    "payments": frozenset({Capability.PAYMENT}),
    # dual: a browser both ingests untrusted pages and can reach the network
    "browser": frozenset({Capability.RECEIVE_UNTRUSTED, Capability.NETWORK_OUT}),
}

# Provider-specific aliases -> canonical kind.
KIND_ALIASES: dict[str, str] = {
    "http": "http_out",
    "https": "http_out",
    "fetch": "http_out",
    "requests": "http_out",
    "bash": "shell",
    "terminal": "shell",
    "python": "code_interpreter",
    "gmail": "email",
    "gmail_inbound": "email_inbound",
    "smtp": "email_send",
    "filesystem": "files",
    "fs": "files",
    "file": "files",
    "gcal": "calendar",
    "google_calendar": "calendar",
    "obsidian": "notes",
    "stripe": "payments",
    "pay": "payments",
}


def canonical_kind(raw_kind: str) -> str:
    """Normalise a provider-specific kind string to a canonical kind.

    Lower-cased and alias-resolved. Unknown kinds pass through unchanged (and
    will resolve to an empty capability set — a NEUTRAL node).
    """
    key = raw_kind.strip().lower()
    return KIND_ALIASES.get(key, key)


def default_capabilities_for(raw_kind: str | None) -> frozenset[Capability]:
    """Return the default capability profile for a (raw) connector kind."""
    if not raw_kind:
        return frozenset()
    return KIND_PROFILES.get(canonical_kind(raw_kind), frozenset())
