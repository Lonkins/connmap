"""Shared helpers for importers: tool-name -> capability mapping.

Both the OpenClaw and MCP importers describe connectors by the *tools* they
expose. This module turns those tool names into :class:`Capability` sets so the
importers stay thin and consistent.
"""

from __future__ import annotations

from collections.abc import Iterable

from connmap.model.connector import Connector
from connmap.model.trust import Capability, default_capabilities_for

TOOL_CAPABILITY: dict[str, Capability] = {
    # receiving untrusted content
    "receive_message": Capability.RECEIVE_UNTRUSTED,
    "read_messages": Capability.RECEIVE_UNTRUSTED,
    "receive": Capability.RECEIVE_UNTRUSTED,
    "poll_inbox": Capability.RECEIVE_UNTRUSTED,
    "browse": Capability.RECEIVE_UNTRUSTED,
    # reading sensitive data
    "read_file": Capability.READ_SENSITIVE,
    "list_directory": Capability.READ_SENSITIVE,
    "read": Capability.READ_SENSITIVE,
    "get_contacts": Capability.READ_SENSITIVE,
    "read_calendar": Capability.READ_SENSITIVE,
    "read_notes": Capability.READ_SENSITIVE,
    # writing sensitive data
    "write_file": Capability.WRITE_SENSITIVE,
    "write": Capability.WRITE_SENSITIVE,
    "edit_note": Capability.WRITE_SENSITIVE,
    "create_event": Capability.WRITE_SENSITIVE,
    # sending messages (exfil vector)
    "send_message": Capability.SEND_MESSAGE,
    "send": Capability.SEND_MESSAGE,
    "reply": Capability.SEND_MESSAGE,
    "send_email": Capability.SEND_MESSAGE,
    # outbound network (exfil vector)
    "fetch": Capability.NETWORK_OUT,
    "http_request": Capability.NETWORK_OUT,
    "post": Capability.NETWORK_OUT,
    "webhook": Capability.NETWORK_OUT,
    # execution (escalation)
    "run": Capability.EXECUTE,
    "exec": Capability.EXECUTE,
    "shell": Capability.EXECUTE,
    "run_command": Capability.EXECUTE,
    # payments
    "pay": Capability.PAYMENT,
    "transfer": Capability.PAYMENT,
    "checkout": Capability.PAYMENT,
}


def capabilities_from_tools(tools: Iterable[str]) -> frozenset[Capability]:
    """Map a list of tool names to the capabilities they imply."""
    caps: set[Capability] = set()
    for tool in tools:
        cap = TOOL_CAPABILITY.get(tool.strip().lower())
        if cap is not None:
            caps.add(cap)
    return frozenset(caps)


def make_connector(
    *,
    connector_id: str,
    name: str,
    raw_kind: str,
    tools: Iterable[str] = (),
    trusted: bool = False,
    description: str = "",
) -> Connector:
    """Build a :class:`Connector`, unioning kind-default and tool capabilities.

    The connector ``kind`` seeds a default capability profile; the declared
    tools refine it. Passing the capabilities explicitly means the connector's
    trust role is correct even when the kind is unknown but the tools are not.
    """
    caps = default_capabilities_for(raw_kind) | capabilities_from_tools(tools)
    return Connector(
        id=connector_id,
        name=name or connector_id,
        kind=raw_kind,
        capabilities=caps,
        trusted=trusted,
        description=description,
    )
