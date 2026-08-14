"""Tests for Ф7 — Vulnerability Prediction (forecast + EPSS integration)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_forecast import exploitability_boost, _file_imports


def test_exploitability_boost_high_epss():
    imports = {"django", "flask"}
    sca = [{"package": "django", "vuln_id": "CVE-2021-1", "cve": "CVE-2021-1"}]
    epss = {"CVE-2021-1": 0.85}
    boost, best, cves = exploitability_boost(imports, sca, epss)
    assert boost == 20
    assert best == 0.85
    assert cves == ["CVE-2021-1"]


def test_exploitability_boost_medium_epss():
    imports = {"requests"}
    sca = [{"package": "requests", "cve": "CVE-2020-1"}]
    epss = {"CVE-2020-1": 0.3}
    boost, best, _ = exploitability_boost(imports, sca, epss)
    assert boost == 10
    assert best == 0.3


def test_exploitability_boost_not_imported():
    imports = {"flask"}
    sca = [{"package": "django", "cve": "CVE-2021-1"}]
    epss = {"CVE-2021-1": 0.9}
    boost, best, cves = exploitability_boost(imports, sca, epss)
    assert boost == 0
    assert best == 0.0
    assert cves == []


def test_exploitability_boost_package_normalization():
    # PyPI hyphen → underscore module name
    imports = {"pillow"}  # actually imported as PIL, but test hyphen normalize
    sca = [{"package": "python-dateutil", "cve": "CVE-2021-2"}]
    epss = {"CVE-2021-2": 0.5}
    # python-dateutil → python_dateutil, not in imports → 0
    boost, best, _ = exploitability_boost(imports, sca, epss)
    assert boost == 0


def test_file_imports(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\nfrom django.conf import settings\n\ndef f():\n    yaml.load(x)\n"
    )
    imports = _file_imports(str(tmp_path / "app.py"))
    assert "yaml" in imports
    assert "django" in imports


def test_file_imports_invalid_file():
    assert _file_imports("/nonexistent/xyz.py") == set()
