# CLI reference

connmap is fully static: every command reads a local config file and nothing
else.

## `connmap analyze`

Build the graph, run the threat engine, and report.

```console
$ connmap analyze CONFIG [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `CONFIG` | Path to the assistant config (`.json`). |
| `-i, --importer TEXT` | Force the format: `openclaw` or `mcp` (auto-detected if omitted). |
| `--json PATH` | Write the JSON report to `PATH`. |
| `--sarif PATH` | Write the SARIF 2.1.0 report to `PATH`. |
| `--html PATH` | Write the self-contained interactive HTML graph to `PATH`. |
| `--policy PATH` | Write the least-privilege policy to `PATH`. |
| `-q, --quiet` | Suppress the console report (still writes artifacts, still sets the exit code). |
| `--exit-zero` | Exit `0` even when findings are present. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean (or findings present with `--exit-zero`). |
| `1` | Findings present. Makes `connmap analyze` a drop-in CI gate. |
| `2` | The config could not be read or parsed. |

### Examples

```bash
# Console report only
connmap analyze assistant.json

# Every artifact at once, no console output
connmap analyze assistant.json \
  --json out/report.json --sarif out/report.sarif \
  --html out/graph.html --policy out/policy.json --quiet

# Force the MCP importer
connmap analyze claude_desktop_config.json --importer mcp
```

## `connmap policy`

Generate the least-privilege policy on its own.

```console
$ connmap policy CONFIG [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `CONFIG` | Path to the assistant config (`.json`). |
| `-i, --importer TEXT` | Force the format: `openclaw` or `mcp`. |
| `-o, --out PATH` | Write the policy to `PATH` (prints to stdout otherwise). |

## `connmap version`

Print the installed version.

## Use in CI

Because `analyze` exits non-zero on findings and emits SARIF, it drops into a
pipeline directly:

```yaml
- run: connmap analyze config.json --sarif connmap.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: connmap.sarif
```
