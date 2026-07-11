# Example configs

Synthetic configurations used by the docs, tests, and quick-start. None of these
describe a real person's setup — they are fixtures.

| File | Format | What it shows |
|------|--------|---------------|
| [`openclaw-vulnerable.json`](openclaw-vulnerable.json) | OpenClaw | WhatsApp (inbound) → files (read) → HTTP (out), permissive routing. connmap reports a confused-deputy path. |
| [`openclaw-hardened.json`](openclaw-hardened.json) | OpenClaw | Same connectors, explicit routing that mediates the `files → http` hop. connmap reports **clean**. |
| [`mcp-vulnerable.json`](mcp-vulnerable.json) | MCP | Telegram + filesystem + shell MCP servers. Shows escalation through a shell executor. |

```bash
connmap analyze examples/openclaw-vulnerable.json
connmap analyze examples/openclaw-hardened.json   # clean
```
