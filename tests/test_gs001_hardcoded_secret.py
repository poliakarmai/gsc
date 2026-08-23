"""tests/test_gs001_hardcoded_secret.py — GS001 positive/negative fixtures.

Covers the demo-password + template-artifact FP filters (100-project benchmark
cluster: ruff `s3cr3t`, sqlalchemy `tiger`, pygoat `<b>anything`, django `%(user)s`)
while preserving weak-but-real teaching creds (vuln-flask `admin123`).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs001_hardcoded_secret as g


def _run(tmp_path: Path) -> list:
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _titles(findings):
    return {f["title"] for f in findings}


def _password_findings(findings):
    return [f for f in findings if f["title"] == "Hardcoded password"]


# ── Positives (must FIRE) ──────────────────────────────────────────────────


def test_real_password_detected(tmp_path):
    (tmp_path / "cfg.py").write_text('DB_PASSWORD = "Sup3rS3cret!2024"\n')
    assert "Hardcoded password" in _titles(_run(tmp_path))


def test_admin123_still_detected(tmp_path):
    # vuln-flask TP — weak-but-real credential must NOT be filtered as demo.
    (tmp_path / "cfg.py").write_text('password = "admin123"\n')
    assert "Hardcoded password" in _titles(_run(tmp_path))


def test_hash_password_still_detected(tmp_path):
    # pygoat stores md5-hashed demo passwords — keep as TP signal.
    (tmp_path / "cfg.py").write_text(
        'password = "65079b006e85a7e798abecb99e47c154"\n'
    )
    assert "Hardcoded password" in _titles(_run(tmp_path))


def test_aws_key_still_detected(tmp_path):
    (tmp_path / "cfg.py").write_text('aws = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "AWS Access Key ID" in _titles(_run(tmp_path))


# ── Negatives (must NOT fire) ──────────────────────────────────────────────


@pytest.mark.parametrize("val", [
    "s3cr3t", "tiger", "jack", "hunter2", "letmein", "qwerty123",
    "iamusedfortesting", "my-super-secret-password", "test-pass-123",
    "changeme", "kwonly", "posonly", "py-polars", "default",
])
def test_demo_password_not_flagged(tmp_path, val):
    (tmp_path / "cfg.py").write_text(f'password = "{val}"\n')
    assert _password_findings(_run(tmp_path)) == []


def test_html_tag_not_flagged(tmp_path):
    (tmp_path / "tpl.py").write_text('password = "<b>anything</b>"\n')
    assert _password_findings(_run(tmp_path)) == []


def test_sql_param_placeholder_not_flagged(tmp_path):
    (tmp_path / "db.py").write_text(
        'sql = "alter user %(user)s identified by %(pw)s"\n'
    )
    assert _password_findings(_run(tmp_path)) == []


def test_no_false_positive_on_clean_code(tmp_path):
    (tmp_path / "clean.py").write_text('x = 42\nprint("hello world")\n')
    assert _run(tmp_path) == []


# ── Helper unit tests ──────────────────────────────────────────────────────


def test_extract_quoted_value():
    assert g._extract_quoted_value('password = "tiger"') == "tiger"
    assert g._extract_quoted_value("password = 'root'") == "root"
    assert g._extract_quoted_value("password") == ""


def test_is_template_artifact():
    assert g._is_template_artifact('<b>anything') is True
    assert g._is_template_artifact('%(user)s') is True
    assert g._is_template_artifact('$(') is True
    assert g._is_template_artifact('Sup3rS3cret!2024') is False


def test_is_demo_password():
    assert g._is_demo_password('password = "tiger"') is True
    assert g._is_demo_password('password = "admin123"') is False
