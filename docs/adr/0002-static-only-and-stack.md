# 2. Static-only analysis and the tool stack

Date: 2026-07-11

## Status

Accepted

## Context

connmap models how data can flow between an AI assistant's connectors and where
that flow is dangerous. There are two ways to learn a connector graph: observe
the assistant at runtime, or read its configuration. Runtime observation means
connecting to live integrations, holding credentials, and intercepting traffic —
operationally heavy, risky, and impossible to run safely in CI or against a
config you were just handed.

## Decision

connmap is **static only**. It reads local configuration through a pluggable
`Importer` and never connects to, authenticates against, or sends data to any
integration. This is a hard invariant, not a default: no code path may open a
network connection to a modelled connector, and generated HTML reports make no
external calls.

Stack:

- **Python 3.12**, packaged with **uv** and **hatchling**.
- **pydantic v2** for the config/graph models and boundary validation — every
  imported config is validated before it becomes a graph.
- **networkx** for graph representation and path analysis (confused-deputy and
  exfil detection are path queries over a directed graph).
- **typer + rich** for the CLI.
- **mypy --strict**, **ruff**, **pytest** enforced in CI; **gitleaks** for
  secret scanning; **pre-commit** to run the same locally.
- Self-contained HTML report (see ADR-0003).

## Consequences

- connmap is safe to run anywhere, needs no secrets, and is trivially testable
  with synthetic fixtures.
- It cannot discover flows that exist only at runtime and are absent from
  config. That is an accepted limitation and a documented non-goal.
- The `Importer` boundary is the single place that turns messy external config
  into validated internal models, keeping the rest of the code total and typed.
