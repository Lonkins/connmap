# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-11

Initial release.

### Added

- **Trust taxonomy** — `untrusted_inbound` / `sensitive_source` /
  `action_or_exfil` / `neutral` roles derived deterministically from a closed
  capability set; canonical connector kinds and profiles.
- **Data-flow graph** over networkx: permissive-default edge synthesis and
  closed-world declared routing with mediation.
- **Importers** for the OpenClaw config schema and the generic MCP-integration
  schema, with format auto-detection and synthetic fixtures.
- **Threat engine** — confused-deputy, privilege-escalation, and unmediated-exfil
  detection, each explained as a concrete attacker chain.
- **Least-privilege policy generator** that severs the dangerous flows (deny /
  require-approval) and iterates to a fixpoint, preserving intended flows.
- **Reporters** — rich CLI, JSON, and SARIF 2.1.0.
- **Self-contained interactive HTML graph** (inline d3, no external calls,
  opens offline), colour-coded by trust role with findings overlaid.
- **CLI** — `connmap analyze` (JSON/SARIF/HTML/policy outputs, CI-friendly exit
  codes) and `connmap policy`.
- **Documentation** — MkDocs Material site with a worked OpenClaw example.

[Unreleased]: https://github.com/Lonkins/connmap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Lonkins/connmap/releases/tag/v0.1.0
