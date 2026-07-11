# Design decisions

connmap records design choices as short Architecture Decision Records under
[`docs/adr/`](https://github.com/Lonkins/connmap/tree/main/docs/adr). The
load-bearing ones:

## Static-only analysis

connmap **never** connects to, authenticates against, or sends data to any
integration. It reads local configuration and models data flow from that alone.
This is a hard invariant, not a default — no code path opens a network
connection to a modelled connector, and generated HTML reports make no external
calls. It means connmap is safe to run anywhere, needs no secrets, and is
trivially testable with synthetic fixtures. The trade-off: connmap cannot see
flows that exist only at runtime and are absent from config. That is an accepted,
documented limitation.

→ [ADR-0002](https://github.com/Lonkins/connmap/blob/main/docs/adr/0002-static-only-and-stack.md)

## Roles colour, capabilities decide

A connector has one trust *role* (for colour and narrative) but a *set* of
capabilities that drive the analysis. This resolves the dual-use problem cleanly:
a chat app is coloured `untrusted_inbound` (where attacker content enters) yet
still counts as an exfil sink during path analysis because it can send.

→ [Trust taxonomy](trust-taxonomy.md)

## Mediation as the single lever

Detection walks only unmediated edges; remediation works by marking the right
hops mediated (or denying them). The same idea powers both the threat engine and
the least-privilege policy generator, and it is why re-analysing a hardened
config is clean.

→ [Threat catalog](threat-catalog.md)

## Self-contained HTML

The report inlines a vendored d3, the styles, the script, and the data, so it
opens offline with no external calls. Data is unicode-escaped JSON inserted via
`textContent`, so config values can't break out of the script block or inject
DOM.

→ [ADR-0003](https://github.com/Lonkins/connmap/blob/main/docs/adr/0003-self-contained-html.md)
