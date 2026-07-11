# Worked example

This walks the [`openclaw-vulnerable.json`](https://github.com/Lonkins/connmap/blob/main/examples/openclaw-vulnerable.json)
fixture end to end: analyse it, read the finding, generate a policy, and confirm
the hardened config is clean. Every output below is real connmap output.

## 1. The config

A personal assistant named *Kai* wired to WhatsApp (inbound), the filesystem
(sensitive), and outbound HTTP — with permissive routing.

```json
{
  "openclaw_version": "1.0",
  "assistant": { "name": "Kai (personal assistant)" },
  "connectors": [
    { "id": "whatsapp", "type": "whatsapp", "tools": ["receive_message", "send_message"] },
    { "id": "files",    "type": "filesystem", "tools": ["read_file", "write_file", "list_directory"] },
    { "id": "http",     "type": "http", "tools": ["fetch"] }
  ],
  "routing": { "mode": "auto" }
}
```

## 2. Analyze

```console
$ connmap analyze examples/openclaw-vulnerable.json
```

```
connmap  ·  3 connectors  ·  4 edges  ·  2 finding(s)
● 1 untrusted_inbound   ● 1 sensitive_source   ● 1 action_or_exfil

╭─ CRITICAL  CD-001  Confused-deputy exfiltration path ─────────────────────────╮
│ whatsapp  →  files  →  http                                                   │
│                                                                               │
│ An attacker plants a crafted message in WhatsApp (an untrusted whatsapp        │
│ channel). Acting as a confused deputy, the assistant follows the embedded      │
│ instruction: it reads Home files and hands the data to Web fetch (http_out).   │
│ Every hop on whatsapp → files → http is unmediated, so attacker-controlled     │
│ input can steer a sensitive read straight into an outbound action.             │
│                                                                                │
│ Fix: Break the final hop files → http: require human approval on it, or deny   │
│ http for any flow that originated at the untrusted source whatsapp.            │
╰────────────────────────────────────────────────────────────────────────────────╯
```

connmap also finds `CD-002` — a **reply-to-attacker** exfil, where the assistant
reads a file and replies over WhatsApp with the contents. The command exits `1`
because findings are present, which makes it usable as a CI gate.

## 3. See the graph

```console
$ connmap analyze examples/openclaw-vulnerable.json --html out/graph.html
```

The HTML is self-contained and opens offline. Nodes are coloured by trust role
(red inbound, amber sensitive, purple action/exfil), directed edges show data
movement, and the findings sidebar lets you click a finding to trace its exact
path — the chain lights up while the rest of the graph dims.

## 4. Generate the policy

```console
$ connmap policy examples/openclaw-vulnerable.json
```

```json
{
  "connmap_policy_version": "1.0",
  "assistant": "Kai (personal assistant)",
  "default": "allow",
  "rules": [
    {
      "from": "files",
      "to": "http",
      "action": "require_approval",
      "reason": "Require human approval on the files → http hop: breaks silent exfiltration into http while still allowing approved, intentional use.",
      "addresses": ["CD-001"]
    },
    {
      "from": "files",
      "to": "whatsapp",
      "action": "require_approval",
      "reason": "Require human approval on the files → whatsapp hop: breaks silent exfiltration into whatsapp while still allowing approved, intentional use.",
      "addresses": ["CD-002"]
    }
  ],
  "rationale": "connmap generated 2 least-privilege rule(s) that sever all 2 detected attack path(s): 0 denied outright, 2 gated behind human approval. Every other data flow remains allowed, so intended behaviour is preserved."
}
```

The policy is **default-allow** with two targeted rules. It requires approval on
exactly the hops that carry sensitive data into a sink — nothing else changes.

## 5. The hardened config is clean

[`openclaw-hardened.json`](https://github.com/Lonkins/connmap/blob/main/examples/openclaw-hardened.json)
applies the same idea: explicit routing that mediates the `files → http` hop.

```console
$ connmap analyze examples/openclaw-hardened.json
```

```
connmap  ·  3 connectors  ·  2 edges  ·  0 finding(s)
● 1 untrusted_inbound   ● 1 sensitive_source   ● 1 action_or_exfil

╭─ ✓ clean ─────────────────────────────────────────────────────────────────────╮
│ No dangerous flows detected. This configuration is clean.                      │
╰────────────────────────────────────────────────────────────────────────────────╯
```

Exit code `0`. The confused-deputy path is gone because the one hop that carried
sensitive data outbound is now mediated — and the engine only walks unmediated
edges.

## A note on escalation

The [`mcp-vulnerable.json`](https://github.com/Lonkins/connmap/blob/main/examples/mcp-vulnerable.json)
fixture shows privilege escalation: a Telegram bot wired alongside a shell MCP
server. connmap flags `telegram → shell`, and the generated policy **denies**
both the direct hop and the alternate path through the filesystem pivot that a
naive one-shot fix would miss — the generator iterates to a fixpoint until the
config is provably clean.
