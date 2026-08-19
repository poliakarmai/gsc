"""Business-risk scoring — pure functions (#1 из «3 киллер-фич»)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_business_risk import business_weight, compute_business_risk, prioritize


def test_business_weight_critical():
    assert business_weight("src/payments/checkout.py") == 3.0


def test_business_weight_normal():
    assert business_weight("src/utils/helpers.py") == 1.0


def test_business_weight_windows_path():
    assert business_weight(r"C:\app\auth\login.py") == 3.0


def test_compute_basic_high_normal():
    r = compute_business_risk({"severity": "HIGH", "file_path": "app/x.py"})
    # 0.8 (HIGH) × 1.0 (biz) × 1.0 (reach) × 1.0 (chain) × 1.0 (epss) = 0.8
    assert abs(r["score"] - 0.8) < 1e-6
    assert r["level"] == "high"
    assert r["critical_path"] is False


def test_compute_critical_path_multiplier():
    r = compute_business_risk({"severity": "HIGH", "file_path": "payments/charge.py"})
    assert abs(r["score"] - 0.8 * 3.0) < 1e-6  # 2.4
    assert r["critical_path"] is True
    assert r["level"] == "critical"


def test_compute_chain_factor():
    f = {"severity": "MEDIUM", "finding_key": "k1", "file_path": "app/x.py"}
    chains = [{"finding_keys": ["k1", "k2", "k3"]}]
    r = compute_business_risk(f, chains=chains)
    # 0.5 (MEDIUM) × 1 × 1 × (1 + 0.2×3) = 0.8
    assert abs(r["score"] - 0.8) < 1e-6
    assert r["chain_len"] == 3


def test_compute_epss_factor():
    f = {"severity": "HIGH", "file_path": "app/x.py",
         "metadata": {"epss": {"score": 0.5}}}
    r = compute_business_risk(f)
    # 0.8 × (0.5 + 0.5) = 0.8
    assert abs(r["score"] - 0.8) < 1e-6


def test_compute_no_chain_no_metadata():
    # финальный smoke: LOW находка без metadata
    r = compute_business_risk({"severity": "LOW", "file_path": "a/b.py"})
    assert abs(r["score"] - 0.2) < 1e-6  # 0.2 (LOW)
    assert r["level"] == "low"


def test_prioritize_sorts_by_business_risk():
    fs = [
        {"severity": "LOW", "file_path": "app/a.py", "finding_key": "low"},
        {"severity": "HIGH", "file_path": "payments/b.py", "finding_key": "high_crit"},
        {"severity": "HIGH", "file_path": "app/c.py", "finding_key": "high_norm"},
    ]
    out = prioritize(fs)
    assert out[0]["finding_key"] == "high_crit"
    # не мутирует исходный список
    assert "metadata" not in fs[0] or "business_risk" not in fs[0].get("metadata", {})
