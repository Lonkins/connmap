# API reference

connmap is usable as a library. The typical pipeline:

```python
from connmap.importers import load_config
from connmap.model.graph import build_graph
from connmap.engine import analyze
from connmap.policy import generate_policy
from connmap.render import render_html

assistant = load_config("assistant.json")     # -> Assistant
graph = build_graph(assistant)                 # -> DataFlowGraph
analysis = analyze(graph)                      # -> Analysis
policy = generate_policy(assistant, analysis)  # -> Policy
html = render_html(graph, analysis)            # -> str (self-contained)
```

## Model

::: connmap.model.connector.Assistant

::: connmap.model.connector.Connector

::: connmap.model.graph.build_graph

::: connmap.model.graph.DataFlowGraph

## Importers

::: connmap.importers.load_config

::: connmap.importers.parse_document

::: connmap.importers.base.ImporterError

## Engine

::: connmap.engine.analyze

::: connmap.engine.findings.Analysis

## Policy

::: connmap.policy.generate_policy

::: connmap.policy.apply_policy

## Rendering

::: connmap.render.render_html
