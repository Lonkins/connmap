"""connmap — data-flow threat mapping for local AI-assistant connectors.

connmap is a fully static analyzer. It reads a local assistant's connector
configuration and models the data flow between connectors; it never connects
to, authenticates against, or sends data to any live integration.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("connmap")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
