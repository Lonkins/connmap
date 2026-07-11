# Writing an importer

An importer turns some assistant's config document into a validated
[`Assistant`](api.md). Everything downstream — graph, engine, policy, reporters —
consumes that one type, so an importer is the *only* place that deals with a
particular config schema.

## The protocol

```python
from collections.abc import Mapping
from typing import Any

from connmap.model.connector import Assistant


class Importer:
    format_name: str

    def matches(self, data: Mapping[str, Any]) -> bool:
        """Cheap heuristic used for format auto-detection."""

    def parse(self, data: Mapping[str, Any]) -> Assistant:
        """Do the real work, or raise ImporterError on malformed input."""
```

`matches` is a fast shape check (usually "is this key present?"). `parse` builds
the `Assistant` and must raise
[`ImporterError`](api.md#connmap.importers.base.ImporterError) on anything it
can't handle — never return a half-built object.

## Building connectors

Don't construct `Connector` by hand. Use the shared helper, which unions the
kind's default capabilities with the ones implied by the declared tools:

```python
from connmap.importers.tools import make_connector

connector = make_connector(
    connector_id="whatsapp",
    name="WhatsApp",
    raw_kind="whatsapp",              # canonicalised + given a default profile
    tools=["receive_message", "send_message"],
    trusted=False,
)
```

Passing the capabilities through the tools means the trust role is correct even
when the `kind` is unknown but the tools are not. See the
[trust taxonomy](trust-taxonomy.md) for the kind and tool mappings.

## Routing

- Leave `routes` empty for a **permissive** assistant — the model may chain any
  enabled tool. This is the honest default for most assistants and is what makes
  confused-deputy attacks possible.
- Emit `Route`s for a **closed-world** allow-list, marking a hop `mediated=True`
  when it passes through a trust boundary (human approval, sanitisation).

## Register it

Add an instance to the registry in
[`connmap/importers/__init__.py`](https://github.com/Lonkins/connmap/blob/main/src/connmap/importers/__init__.py),
in detection order (most specific `matches` first):

```python
IMPORTERS: tuple[Importer, ...] = (MCPImporter(), OpenClawImporter(), MyImporter())
```

## Test it

Add a **synthetic** fixture (never a real config) and assert both the happy path
and the boundary errors:

```python
def test_my_importer_roundtrips() -> None:
    assistant = parse_document(MY_FIXTURE)
    assert assistant.source_format == "myformat"
    graph = build_graph(assistant)
    # ... assert the expected roles, edges, or findings
```

## Reference

::: connmap.importers.base.Importer

::: connmap.importers.tools.make_connector
