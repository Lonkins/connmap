# Trust taxonomy

connmap reasons about two things for every connector: **what it can do**
(capabilities) and **where it sits in the trust landscape** (its role). Roles
are for colour and narrative; capabilities drive the analysis.

## Trust roles

Every connector node is classified into exactly one role.

| Role | Colour | Meaning | Examples |
|------|--------|---------|----------|
| `untrusted_inbound` | 🔴 red | Ingests attacker-influenceable content | WhatsApp, Telegram, Signal, SMS, email, web, webhooks |
| `sensitive_source` | 🟡 amber | Holds private data | files, contacts, calendar, notes, photos |
| `action_or_exfil` | 🟣 purple | Performs privileged actions or moves data out | shell, outbound HTTP, send-message, payments |
| `neutral` | ⚪ grey | No modelled risk | unknown kinds, or an inbound channel marked `trusted` |

A single connector often does more than one thing — a chat app both **receives**
untrusted content and can **send** messages. The role names the connector's
*dominant* risk (inbound wins, because it is where attacker content enters), but
its send capability still makes it a valid exfil sink during path analysis.

## Capabilities

Roles are derived from a closed set of capabilities:

| Capability | What it means |
|------------|---------------|
| `receive_untrusted` | Accepts content an attacker can influence |
| `read_sensitive` | Reads private data |
| `write_sensitive` | Modifies private data |
| `send_message` | Sends to a channel/recipient (an exfil vector) |
| `network_out` | Arbitrary outbound network (an exfil vector) |
| `execute` | Runs shell/code (a universal escalation primitive) |
| `payment` | Moves money (high-value action and exfil vector) |

### Classification rule

Deterministic and priority-ordered:

1. Has `receive_untrusted` (and is not marked `trusted`) → **untrusted_inbound**
2. Otherwise, has any sink capability (`send_message`, `network_out`, `execute`,
   `payment`) → **action_or_exfil**
3. Otherwise, has a sensitive capability → **sensitive_source**
4. Otherwise → **neutral**

The two capability groupings the engine cares most about:

- **Exfil sinks** — `send_message`, `network_out`, `payment`: data (or money)
  leaves the trust boundary.
- **Executor** — `execute`: the universal primitive; shell can read, write, and
  reach the network on its own.

## How kinds map to capabilities

Importers normalise provider-specific connector names to a **canonical kind**
(e.g. `bash → shell`, `gmail → email`, `filesystem → files`), and each canonical
kind seeds a default capability profile. Declared tools then refine it. An
unknown kind maps to *no* capabilities — a neutral node — rather than guessing.

Marking a connector `trusted: true` suppresses its inbound classification, for a
channel the operator genuinely vouches for (say a private, self-only webhook).

The taxonomy lives in one module and is the single source of truth:

::: connmap.model.trust.classify_role

::: connmap.model.trust.TrustRole
