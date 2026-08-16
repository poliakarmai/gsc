"""Тесты gsc_fix_quality — 3-осевая оценка качества патча."""
import json
import tempfile
from pathlib import Path

from gsc_fix_quality import FixQuality, score_fix, score_from_evidence_json
from gsc_proofoffix import FixEvidence


def _ev(finding_key="k1", file_path="app.py", patch=None, verified=True):
    return FixEvidence(
        finding_key=finding_key,
        rule_id="GS005",
        file_path=file_path,
        verified=verified,
        patch=patch or [],
    )


def test_good_fix_minimal_in_scope_with_test():
    ev = _ev(patch=[{"file": "app.py"}, {"file": "tests/test_app.py"}])
    q = score_fix(ev)
    assert isinstance(q, FixQuality)
    assert q.verified is True
    assert q.minimality == 0.85
    assert q.regression_risk == 0.0
    assert q.test_coverage == 1.0
    assert q.verdict == "good"
    assert q.score > 0.9


def test_risky_fix_many_out_of_scope_no_test():
    ev = _ev(patch=[{"file": "lib/a.py"}, {"file": "lib/b.py"}, {"file": "lib/c.py"}])
    q = score_fix(ev)
    assert q.regression_risk == 1.0
    assert q.test_coverage == 0.0
    assert q.verdict == "risky"
    assert q.score < 0.5


def test_acceptable_partial_scope_no_test():
    # 1 файл в scope + 1 вне scope, без теста → 0.5*0.85 + 0.3*0.5 + 0 = 0.575
    ev = _ev(patch=[{"file": "app.py"}, {"file": "lib/util.py"}])
    q = score_fix(ev)
    assert q.minimality == 0.85
    assert q.regression_risk == 0.5
    assert q.test_coverage == 0.0
    assert q.score == 0.575
    assert q.verdict == "acceptable"


def test_score_from_evidence_json():
    ev = _ev(patch=[{"file": "app.py"}])
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fix.json"
        p.write_text(json.dumps(ev.to_dict()))
        q = score_from_evidence_json(str(p))
        assert q.finding_key == "k1"
        assert q.score == 0.8
