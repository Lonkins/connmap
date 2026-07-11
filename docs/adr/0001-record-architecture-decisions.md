# 1. Record architecture decisions

Date: 2026-07-11

## Status

Accepted

## Context

connmap is built autonomously and open source from the first commit. Design
choices need a durable, reviewable record so contributors (and future us)
understand *why* the code looks the way it does, not just *what* it does.

## Decision

We keep lightweight Architecture Decision Records (ADRs) in `docs/adr/`, one
Markdown file per decision, numbered sequentially. Each records context, the
decision, and its consequences. ADRs are immutable once accepted; a later ADR
supersedes an earlier one rather than editing it.

## Consequences

- Every non-obvious design choice has a paper trail.
- PRs that change direction reference or add an ADR.
- The format is deliberately minimal — the friction to add one stays low.
