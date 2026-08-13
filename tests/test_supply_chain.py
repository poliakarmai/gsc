"""Unit tests for gsc_supply_chain_chains (cross-layer code x dependency chains)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import gsc_supply_chain_chains as sc


def test_find_dependency_usage(tmp_path):
    (tmp_path / "app.py").write_text("import requests\nimport os\nx = requests.get('http://x')\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "mod.py").write_text("from fastapi import FastAPI\n")
    (tmp_path / "commented.py").write_text("# import requests (comment, must be ignored)\n")

    hits = sc.find_dependency_usage(tmp_path, "requests")
    files = [h["file"] for h in hits]
    assert any(f.endswith("app.py") for f in files)
    assert all(not f.endswith("commented.py") for f in files)  # AST ignores comments

    hits2 = sc.find_dependency_usage(tmp_path, "fastapi")
    assert any(h["file"].endswith("nested/mod.py") for h in hits2)


def test_compose_supply_chains(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    (tmp_path / "app.py").write_text("import requests\nrequests.get('http://x')\n")

    def fake_osv(packages, db=None):
        out = {}
        for p in packages:
            if p.name == "requests":
                out[(p.ecosystem, p.name, p.version)] = [
                    {"id": "GHSA-test", "database_specific": {"severity": "HIGH"}}
                ]
        return out

    monkeypatch.setattr(sc, "query_osv", fake_osv)
    findings = [{"rule_id": "GS005", "file_path": "app.py",
                 "category": "CRITICAL", "finding_key": "fk1"}]
    chains = sc.compose_supply_chains(tmp_path, findings)
    assert len(chains) >= 1
    c = chains[0]
    assert c["package"] == "requests"
    assert c["version"] == "2.19.0"
    assert c["cve"] == "GHSA-test"
    assert c["dep_severity"] == "HIGH"
    assert c["composed_severity"] == "CRITICAL"  # code CRITICAL >= dep HIGH
    assert c["usage_file"].endswith("app.py")
    assert 7.0 <= c["combined_cvss"] <= 10.0


def test_no_link_when_dep_not_imported(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    (tmp_path / "app.py").write_text("import os\nprint('no requests here')\n")

    def fake_osv(packages, db=None):
        return {("PyPI", "requests", "2.19.0"):
                [{"id": "GHSA-x", "database_specific": {"severity": "HIGH"}}]}

    monkeypatch.setattr(sc, "query_osv", fake_osv)
    findings = [{"rule_id": "GS005", "file_path": "app.py",
                 "category": "HIGH", "finding_key": "fk1"}]
    assert sc.compose_supply_chains(tmp_path, findings) == []
