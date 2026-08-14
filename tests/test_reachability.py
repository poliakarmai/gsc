"""Tests for Reachability Analysis (Ф5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_reachability import (
    collect_python_usage, is_reachable, module_names_for_package,
)


def test_collect_imports_and_calls(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\nimport requests\n\ndef f():\n    yaml.load(data)\n    requests.get(url)\n"
    )
    usage = collect_python_usage(tmp_path)
    assert "yaml" in usage["imports"]
    assert "requests" in usage["imports"]
    assert "load" in usage["calls"]
    assert "get" in usage["calls"]


def test_skips_venv_and_pycache(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "x.py").write_text("import secret\n")
    (tmp_path / "real.py").write_text("import flask\n")
    usage = collect_python_usage(tmp_path)
    assert "secret" not in usage["imports"]
    assert "flask" in usage["imports"]


def test_is_reachable_via_mapping():
    usage = {"imports": {"yaml", "requests"}, "calls": set()}
    assert is_reachable("PyYAML", usage) is True     # via PACKAGE_IMPORT_MAP
    assert is_reachable("requests", usage) is True


def test_is_not_reachable():
    usage = {"imports": {"flask"}, "calls": set()}
    assert is_reachable("django", usage) is False


def test_is_reachable_by_call():
    usage = {"imports": set(), "calls": {"load"}}
    assert is_reachable("PyYAML", usage, vulnerable_funcs={"load"}) is True


def test_module_names_mapping():
    assert "yaml" in module_names_for_package("PyYAML")
    assert "pil" in module_names_for_package("Pillow")


def test_sca_findings_downgrade_not_reachable():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="django", version="2.2", ecosystem="PyPI",
                  manifest="requirements.txt", line=1, raw="django==2.2")
    osv = {("PyPI", "django", "2.2"): [{
        "id": "CVE-2020-1",
        "summary": "x",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"flask"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "not_reachable"
    assert findings[0]["severity"] == "HIGH"          # CRITICAL → HIGH downgrade
    assert findings[0]["metadata"]["original_severity"] == "CRITICAL"


def test_sca_findings_reachable_keeps_severity():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="django", version="2.2", ecosystem="PyPI",
                  manifest="requirements.txt", line=1, raw="django==2.2")
    osv = {("PyPI", "django", "2.2"): [{
        "id": "CVE-2020-1",
        "summary": "x",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"django"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "reachable"
    assert findings[0]["severity"] == "CRITICAL"
