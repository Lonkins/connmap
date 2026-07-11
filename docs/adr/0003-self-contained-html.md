# 3. Self-contained HTML report

Date: 2026-07-11

## Status

Accepted

## Context

The HTML report must open offline, make no external network calls, and render a
trust-coloured, interactive graph with findings overlaid. "No external calls" is
the load-bearing requirement: the file may be opened from disk, emailed, or
committed, and must work with no network.

## Decision

The report is a single HTML document with **everything inlined**: a vendored
copy of d3 v7.9.0 (`src/connmap/render/assets/d3.v7.min.js`), the stylesheet,
the app script, and the analysis data. No CDN, fonts, or fetches. d3 is the
mature, well-tested choice for force-directed graphs, and vendoring it — rather
than fetching at runtime or hand-rolling a layout — is what makes the artifact
genuinely self-contained. Its ISC licence is recorded in `NOTICE`.

The analysis data is embedded as JSON with `<`, `>`, and `&` escaped to their
unicode forms — the standard safe way to put JSON inside an HTML `<script>` — so
a connector name containing `</script>` or markup cannot break out. The client
inserts every piece of text via `textContent`, never `innerHTML`, so no config
value can inject DOM.

## Consequences

- Each report is ~290 KB (d3 dominates). Acceptable for a self-contained local
  artifact; the alternative (an external `<script src>`) would violate the
  no-network requirement.
- We track a third-party minified asset. It is pinned to a specific version and
  attributed in `NOTICE`.
- The renderer has no server component and needs no build step; the wheel ships
  the assets as package data.
