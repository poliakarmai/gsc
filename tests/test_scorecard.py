"""Developer scorecard — pure scoring (#3 из «3 киллер-фич»)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_scorecard import compute_dev_score


def test_zero_introduced():
    r = compute_dev_score(0, 0, 0)
    assert r["score"] == 0.0
    assert r["debt_cleared_rate"] == 0.0


def test_full_cleanup():
    r = compute_dev_score(10, 10, 0)
    assert r["debt_cleared_rate"] == 1.0
    assert r["score"] == 1.0


def test_half_cleanup():
    r = compute_dev_score(10, 5, 0)
    assert abs(r["score"] - 0.5) < 1e-9


def test_verification_bonus():
    # 10 introduced, 10 fixed, 2 confirmed → bonus = 0.1 × (2/10) = 0.02
    r = compute_dev_score(10, 10, 2)
    assert abs(r["verification_bonus"] - 0.02) < 1e-9
    assert abs(r["score"] - 1.0 * 1.02) < 1e-9


def test_fixed_cannot_exceed_introduced():
    r = compute_dev_score(5, 99, 99)
    assert r["fixed"] == 5
    assert r["confirmed"] == 5


def test_negative_clamped():
    r = compute_dev_score(-3, -1, -1)
    assert r["introduced"] == 0
    assert r["score"] == 0.0
