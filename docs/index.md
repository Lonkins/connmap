# connmap

**Data-flow threat mapping for local AI-assistant connectors.**

Point connmap at a local AI assistant's connector configuration. It builds a
**trust-annotated data-flow graph**, finds **confused-deputy** and
**exfiltration** paths, and generates a **least-privilege policy** that severs
the dangerous flows while keeping the intended ones.

!!! info "connmap is fully static"
    It reads configuration you already have on disk. It never connects to,
    authenticates against, or sends data to any integration. No API keys. No
    network. The HTML report it produces opens offline.

## The problem in one paragraph

An assistant that reads your WhatsApp *and* your files *and* can make outbound
HTTP calls is a **confused deputy** waiting to happen. Anyone who can get a
message in front of it — an untrusted inbound channel — can try to make it read
something sensitive and then ship the result out, all with the assistant's own
privileges. The wiring that makes the assistant useful is the same wiring that
makes this attack possible. connmap makes that wiring visible and tells you
which edges to cut.

## What it does

1. **Imports** an assistant's config through a pluggable importer (OpenClaw and
   generic MCP ship in the box).
2. **Builds a trust-annotated graph** — every connector is classified by
   [trust role](trust-taxonomy.md).
3. **Maps threats** — confused-deputy paths, privilege escalation, and
   unmediated exfil, each explained as a concrete attacker chain
   ([threat catalog](threat-catalog.md)).
4. **Generates a least-privilege policy** that breaks the dangerous flows.
5. **Reports** as a rich CLI summary, JSON, SARIF, and a self-contained
   interactive HTML graph.

## Install

```bash
uv tool install connmap        # or: pipx install connmap
```

## 30-second tour

```bash
# Flags a confused-deputy path and exits non-zero
connmap analyze examples/openclaw-vulnerable.json

# The same connectors, hardened — clean
connmap analyze examples/openclaw-hardened.json

# Emit the policy that severs the dangerous flows
connmap policy examples/openclaw-vulnerable.json
```

Start with the [worked example](example.md).

## Non-goals

connmap is **not** a local-machine credential auditor and **not** a static
config-rule linter. It models **cross-integration data flow**. It does no
runtime interception and never authenticates a connector.
