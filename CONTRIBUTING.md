# Contributing to connmap

Thanks for your interest. connmap is a small, focused tool and we want to
keep it that way. Contributions that sharpen the trust taxonomy, add
importers, or improve threat detection are especially welcome.

## Ground rules

- Be respectful. See the [Code of Conduct](CODE_OF_CONDUCT.md).
- Analysis stays **static and offline**. No feature may connect to a live
  integration, authenticate, or require a paid service. This is a hard
  design constraint (see [`docs/adr/`](docs/adr/)).
- Only **synthetic fixtures** go in the repo. Never commit a real
  assistant config, secret, token, or PII.

## Development setup

connmap uses [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Lonkins/connmap
cd connmap
uv sync --all-extras --dev
uv run connmap --help
```

Install the git hooks (they run gitleaks, ruff, and mypy):

```bash
uv run pre-commit install
```

## The checks

Everything CI runs, you can run locally:

```bash
uv run ruff format .        # format
uv run ruff check --fix .   # lint
uv run mypy                 # types (strict)
uv run pytest --cov=connmap # tests + coverage
```

All four must pass. CI enforces the same set plus a gitleaks secret scan.
Never bypass a failing hook with `--no-verify` — fix the cause.

## Workflow

1. Branch off `main`: `git switch -c feat/my-change`.
2. Write the change **with tests and docs**. New detection rules need a
   fixture that triggers them and one that is clean.
3. Keep commits atomic and use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
4. Open a PR against `main`. CI must be green.
5. Squash-merge once approved.

## Adding an importer

See the [importer-authoring guide](https://lonkins.github.io/connmap/importers/).
In short: implement the `Importer` protocol, register it, and add a
round-trip test against a synthetic fixture.

## Adding a threat rule

A rule is a function over the graph that yields `Finding`s. Add it to the
engine, give every finding a concrete attacker narrative, and cover it
with a fixture that fires and one that stays clean.

## Releasing

Releases are cut from tags and published to PyPI via **Trusted Publishing**
(OpenID Connect — no stored tokens).

1. Update `CHANGELOG.md` and bump `version` in `pyproject.toml`.
2. One-time PyPI setup (maintainer, free): create the `connmap` project's
   [trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
   pointing at this repo, workflow `release.yml`, environment `pypi`. Then set
   the repository variable `PUBLISH_TO_PYPI=true`.
3. Tag and push: `git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0`.
   The `release` workflow builds, validates, and (once step 2 is done)
   publishes. Until then the publish job is skipped, so tagging is always safe.

