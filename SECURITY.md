# Security Policy

## Scope and threat model

connmap is a **static analysis** tool. It reads local AI-assistant
configuration files and models the data flow between connectors. It does
**not**:

- connect to, authenticate against, or send data to any live integration;
- execute connector code or tools;
- require any API key, token, or credential.

All analysis happens offline over configuration you already have on disk.
Generated HTML reports are self-contained and make no external network
calls.

## Handling sample configs

Real assistant configs can contain sensitive routing details, account
names, or endpoints. **Only synthetic fixtures live in this repository.**
When you run connmap against a real config, keep that file out of version
control (`.env`, untracked paths). connmap never uploads what it reads.

## Reporting a vulnerability

If you find a security issue in connmap itself, please report it
privately rather than opening a public issue:

- Use GitHub's **[private vulnerability reporting](https://github.com/Lonkins/connmap/security/advisories/new)**, or
- email **tomprice13@pm.me** with the details and a proof of concept.

Please include:

- affected version / commit,
- reproduction steps or a minimal fixture,
- impact assessment.

We aim to acknowledge reports within 5 working days and to ship a fix or
mitigation for confirmed issues as promptly as is practical. Coordinated
disclosure is appreciated.

## Supported versions

connmap is pre-1.0; security fixes land on `main` and in the latest
released version.
