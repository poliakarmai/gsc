"""GSC Threat Model DREAD/PASTA tests."""
from gsc_threat_model import dread_score, apply_dread, pasta_stages, PASTA_STAGES


def test_dread_sql_critical():
    d = dread_score({"risk": "CRITICAL", "surface": "SQL injection in login",
                     "cwe_hint": ["CWE-89"]})
    assert d["total"] >= 40
    assert d["level"] == "CRITICAL"


def test_dread_info_low():
    d = dread_score({"risk": "LOW", "surface": "verbose error", "cwe_hint": []})
    assert d["total"] < 30
    assert d["level"] in ("LOW", "MEDIUM")


def test_dread_axes_bounded():
    d = dread_score({"risk": "HIGH", "surface": "xss", "cwe_hint": ["CWE-79"]})
    for axis in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"):
        assert 0 <= d[axis] <= 10


def test_apply_dread():
    model = {"attack_surfaces": [{"surface": "x", "risk": "HIGH", "cwe_hint": ["CWE-79"]}]}
    apply_dread(model)
    assert "dread" in model["attack_surfaces"][0]


def test_pasta_stages():
    ctx = {"route_count": 5, "auth_files": [], "configs": {}}
    model = {"summary": "s", "trust_boundaries": [], "attack_surfaces": []}
    stages = pasta_stages(ctx, model)
    assert len(stages) == 7
    assert stages[0]["stage"].startswith("1.")
    assert stages[6]["stage"].startswith("7.")
