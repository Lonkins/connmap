# connmap

**Data-flow threat mapping for local AI-assistant connectors.**

[![CI](https://github.com/Lonkins/connmap/actions/workflows/ci.yml/badge.svg)](https://github.com/Lonkins/connmap/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2.svg)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Point connmap at a local AI assistant's connector configuration. It builds a
**trust-annotated data-flow graph**, finds **confused-deputy** and
**exfiltration** paths, and generates a **least-privilege policy** that severs
the dangerous flows while keeping the intended ones.

> connmap is **fully static**. It reads config you already have on disk. It
> never connects to, authenticates against, or sends data to any integration.
> No API keys. No network. The HTML report it produces opens offline.

---

## The problem

A personal AI assistant that reads your WhatsApp *and* your files *and* can make
outbound HTTP calls is a **confused deputy** waiting to happen. An attacker who
can get a message in front of the assistant (an untrusted inbound channel) can
try to make it read something sensitive and then ship the result out — all with
the assistant's own privileges. The wiring that makes the assistant useful is
exactly the wiring that makes this attack possible.

connmap makes that wiring visible and tells you which edges to cut.

## What it does

1. **Imports** an assistant's integration config through a pluggable
   `Importer`. Ships importers for the **OpenClaw** config schema and a
   **generic MCP-integration** schema.
2. **Builds a trust-annotated graph**. Every connector is classified by trust
   role:
   - `untrusted_inbound` — WhatsApp, Telegram, Signal, SMS, email, web
   - `sensitive_source` — files, contacts, calendar, notes
   - `action_or_exfil` — shell, outbound HTTP, send-message, payments
3. **Maps threats** — confused-deputy paths, privilege-escalation chains, and
   unmediated exfil routes. Each finding is a concrete attacker narrative naming
   the exact connector chain.
4. **Generates a least-privilege policy** — an allow/deny policy per
   connector/tool that breaks the dangerous flows, in a form the assistant can
   consume, with a human-readable rationale.
5. **Reports** as a rich CLI summary, JSON, SARIF, and a self-contained
   interactive HTML graph colour-coded by trust role with findings overlaid.

## Install

```bash
uv tool install connmap        # or: pipx install connmap
```

From source:

```bash
git clone https://github.com/Lonkins/connmap
cd connmap
uv sync --all-extras --dev
uv run connmap --help
```

## Quick start

```bash
# Analyze an OpenClaw config and print the report
connmap analyze examples/openclaw-vulnerable.json

# Emit every artifact (console report still prints unless --quiet)
connmap analyze examples/openclaw-vulnerable.json \
  --json out/report.json --sarif out/report.sarif \
  --html out/graph.html --policy out/policy.json

# Generate a least-privilege policy that severs the dangerous flows
connmap policy examples/openclaw-vulnerable.json --out out/policy.json
```

Run it against the hardened config and the confused-deputy finding is gone:

```bash
connmap analyze examples/openclaw-hardened.json   # clean
```

## Example output

```
connmap  ·  4 connectors  ·  3 edges  ·  1 finding

CRITICAL  confused-deputy  CD-001
  whatsapp (untrusted_inbound) → files (sensitive_source) → http_out (action_or_exfil)

  An attacker sends a crafted WhatsApp message. The assistant, acting as a
  confused deputy, reads a sensitive file and forwards its contents over
  outbound HTTP to an attacker-controlled endpoint. Nothing mediates the
  inbound instruction before it reaches a privileged action.

  Fix: deny http_out when the triggering context originates from whatsapp,
  or require human approval on the files → http_out hop.
```

## Trust taxonomy & threat catalog

The full taxonomy, the threat catalog, and a guide to writing your own importer
live in the [documentation](https://lonkins.github.io/connmap/).

## Non-goals

connmap is **not** a local-machine credential auditor and **not** a static
config-rule linter. It models **cross-integration data flow** — how a message
from an untrusted channel can reach a sensitive read and then an outbound
action. It does no runtime interception and never authenticates a connector.

## License

[Apache-2.0](LICENSE) © Tom Price
