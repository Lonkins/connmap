# Threat catalog

connmap runs three detection rules over the **unmediated** slice of the graph —
a hop marked `mediated` (human approval, sanitisation) breaks a chain, so it is
excluded from the paths the engine walks. Every finding names the exact
connector chain and carries a concrete attacker narrative, a fix, and a stable
code.

## `CD` — Confused deputy

**Untrusted inbound → sensitive read → exfil sink**, every hop unmediated.

The assistant is tricked into using its own privileges on the attacker's behalf:
a crafted message steers a sensitive read, and the result flows out. This
includes **reply-to-attacker exfil**, where a chat app that both receives and
sends is used to read a file and reply to the sender with its contents.

!!! example "Attacker narrative"
    An attacker plants a crafted message in WhatsApp (an untrusted whatsapp
    channel). Acting as a confused deputy, the assistant follows the embedded
    instruction: it reads Home files and hands the data to Web fetch. Every hop
    on `whatsapp → files → http` is unmediated, so attacker-controlled input can
    steer a sensitive read straight into an outbound action.

Severity: **critical**.

## `PE` — Privilege escalation

**Untrusted inbound → executor (shell)**, unmediated.

Shell is a universal primitive — with it, an attacker isn't limited to one
sink; they can read, write, and reach the network at will. A message that can
reach an executor is a message that can run arbitrary code with the assistant's
privileges.

Severity: **critical**.

## `EX` — Unmediated exfil

**Sensitive source → exfil sink**, unmediated, with **no untrusted inbound
wired to that source yet**.

A latent egress route. There is no entry point steering it today, but the data
*can* leave with nothing in between. Add any inbound wiring — or compromise an
upstream — and it becomes a confused deputy. Reported separately so it doesn't
hide behind a config that happens to lack an inbound connector right now.

Severity: **high**.

## Why mediation matters

The engine walks only unmediated edges. That single idea unifies detection and
remediation: the [least-privilege policy](example.md) hardens a config precisely
by marking the right hops as mediated (or denying them), and re-analysis of the
hardened config walks a graph where the dangerous paths no longer exist.

## Finding fields

::: connmap.engine.findings.Finding
    options:
      show_root_heading: true
      members: false
