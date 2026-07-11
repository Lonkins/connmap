"""The Importer protocol and shared error type."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from connmap.model.connector import Assistant


class ImporterError(ValueError):
    """Raised when a config cannot be read or parsed into an Assistant."""


@runtime_checkable
class Importer(Protocol):
    """Turns a parsed config document into a validated :class:`Assistant`.

    An importer is stateless. ``matches`` is a cheap heuristic used for format
    auto-detection; ``parse`` does the real work and raises
    :class:`ImporterError` on malformed input.
    """

    format_name: str

    def matches(self, data: Mapping[str, Any]) -> bool:
        """Return True if this importer recognises the document shape."""
        ...

    def parse(self, data: Mapping[str, Any]) -> Assistant:
        """Parse a config document into an Assistant, or raise ImporterError."""
        ...
