"""Тесты gsc_attack_graph — Mermaid-экспорт attack chains."""
import json
import tempfile
from pathlib import Path

from gsc_attack_graph import chains_to_mermaid, render_attack_graph


def test_chains_to_mermaid_basic():
    chains = [
        {
            "chain_key": "c1",
            "composed_severity": "HIGH",
            "finding_keys": ["abc123", "def456"],
            "narrative": "token leak enables SQL injection",
        }
    ]
    md = chains_to_mermaid(chains)
    assert md.startswith("flowchart LR")
    assert 'n0_0["abc123"]' in md
    assert 'n0_1["def456"]' in md
    assert "-->|HIGH|" in md
    assert "classDef high fill:#ff7a45" in md
    assert "token leak enables SQL injection" in md


def test_chains_to_mermaid_empty():
    md = chains_to_mermaid([])
    assert md.startswith("flowchart LR")
    assert "start" in md


def test_chains_to_mermaid_unknown_severity():
    md = chains_to_mermaid([{"composed_severity": "WHATEVER", "finding_keys": ["k"]}])
    assert 'n0_0["k"]' in md
    assert "-->|WHATEVER|" in md


def test_render_attack_graph_writes_file():
    with tempfile.TemporaryDirectory() as d:
        scan = Path(d) / "scan.json"
        out = Path(d) / "attack_paths.md"
        scan.write_text(json.dumps({
            "chains": [{
                "chain_key": "c1",
                "composed_severity": "CRITICAL",
                "finding_keys": ["x1", "x2"],
                "narrative": "",
            }]
        }))
        result = render_attack_graph(str(scan), str(out))
        assert result == str(out)
        content = out.read_text()
        assert "```mermaid" in content
        assert "flowchart LR" in content
        assert "classDef critical" in content


def test_render_attack_graph_no_chains():
    with tempfile.TemporaryDirectory() as d:
        scan = Path(d) / "scan.json"
        out = Path(d) / "attack_paths.md"
        scan.write_text(json.dumps({"findings": []}))
        render_attack_graph(str(scan), str(out))
        assert out.exists()
