"""HTML renderer: self-contained, offline, correctly populated."""

from __future__ import annotations

from pathlib import Path

from connmap.engine import analyze
from connmap.importers import load_config
from connmap.model.connector import Assistant, Connector
from connmap.model.graph import build_graph
from connmap.render import build_graph_data, render_html

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _render(name: str) -> str:
    graph = build_graph(load_config(EXAMPLES / name))
    return render_html(graph, analyze(graph))


def test_html_is_self_contained_and_populated() -> None:
    html = _render("openclaw-vulnerable.json")
    assert html.startswith("<!doctype html>")
    assert "window.CONNMAP_DATA" in html
    assert "d3js.org" in html  # the inlined d3 bundle
    assert "CD-001" in html
    assert "whatsapp" in html


def test_html_makes_no_external_calls() -> None:
    html = _render("openclaw-vulnerable.json")
    # No external scripts, stylesheets, or fetches.
    assert "<script src" not in html
    assert "<link" not in html
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "cdn.jsdelivr" not in html


def test_html_clean_config_has_no_findings() -> None:
    html = _render("openclaw-hardened.json")
    assert '"findings": []' in html
    assert "clean" in html.lower()


def test_graph_data_shape() -> None:
    graph = build_graph(load_config(EXAMPLES / "openclaw-vulnerable.json"))
    data = build_graph_data(graph, analyze(graph))
    assert data["counts"]["connectors"] == 3
    assert {n["id"] for n in data["nodes"]} == {"whatsapp", "files", "http"}
    assert data["findings"]
    assert data["findings"][0]["chain"][0] == "whatsapp"


def test_html_escapes_script_breakout_in_data() -> None:
    # A connector name containing </script> must not break out of the block.
    config = Assistant(
        name="evil",
        connectors=(
            Connector(id="x", name="</script><b>pwn", kind="whatsapp"),
            Connector(id="files", kind="files"),
        ),
    )
    html = render_html(build_graph(config), analyze(build_graph(config)))
    assert "</script><b>pwn" not in html
    assert "\\u003c/script\\u003e" in html
