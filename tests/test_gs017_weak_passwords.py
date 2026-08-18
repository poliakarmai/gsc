"""tests/test_gs017_weak_passwords.py — positive/negative fixtures for GS017.

Covers the precision fixes (self-reference, path exclusion, KEY narrowing,
placeholder filtering, mixed-case length gate, path values, commented
placeholders) plus the must-still-fire TP cases. The .env / Dockerfile
branches are exercised end-to-end now that get_files() collects dotfiles.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs017_weak_passwords as gs017


@pytest.fixture()
def scan(tmp_path):
    def _scan(files: dict[str, str]) -> list:
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        ctx = AuditContext(project="test", path=tmp_path)
        return gs017.detect(ctx)
    return _scan


def _titles(fs):
    return [f["title"] for f in fs]


# ── positive (must still fire) ─────────────────────────────────────────────

def test_default_creds(scan):
    fs = scan({"app.py": 'admin = "admin"\n'})
    assert any("Default credentials" in t for t in _titles(fs))


def test_weak_db_string(scan):
    fs = scan({"config.py": 'DB_URL = "postgres://admin:password@db:5432/app"\n'})
    assert any("connection string" in t for t in _titles(fs))


def test_hardcoded_weak_password(scan):
    fs = scan({"app.py": 'PASSWORD = "admin123"\n'})
    assert any("Hardcoded password variable" in t for t in _titles(fs))


def test_weak_policy(scan):
    fs = scan({"config.py": "MIN_PASSWORD_LENGTH = 6\n"})
    assert any("Weak password policy" in t for t in _titles(fs))


def test_commented_password(scan):
    fs = scan({"app.py": "# password: hunter2\n"})
    assert any("Password visible in comment" in t for t in _titles(fs))


def test_mixed_case_short_fires(scan):
    fs = scan({"app.py": 'PASSWORD = "Pass1234"\n'})
    assert any("Hardcoded password variable" in t for t in _titles(fs))


def test_summer_fires(scan):
    fs = scan({"app.py": 'DB_PASS = "Summer2024"\n'})
    assert any("Hardcoded password variable" in t for t in _titles(fs))


def test_short_env_password(scan):
    fs = scan({".env": "PASSWORD=1234\n"})
    assert any("Very short password" in t for t in _titles(fs))


def test_api_key_env_fires(scan):
    fs = scan({".env": "API_KEY=abc\n"})
    assert any("Very short password" in t for t in _titles(fs))


def test_docker_default_password(scan):
    fs = scan({"Dockerfile": "ENV POSTGRES_PASSWORD admin\n"})
    assert any("Docker default password" in t for t in _titles(fs))


# ── negative (FP fixes — must NOT fire) ────────────────────────────────────

def test_self_reference_ignored(scan):
    fs = scan({"app.py": 'SECRET = "SECRET"\nPASSWORD = "password"\n'})
    assert not fs


def test_benchmark_path_excluded(scan):
    fs = scan({"benchmark/real_world/x/app.py": 'PASSWORD = "admin123"\n'})
    assert not fs


def test_examples_path_excluded(scan):
    fs = scan({"examples/app.py": 'SECRET = "s3cr3t"\n'})
    assert not fs


def test_mixed_case_long_ignored(scan):
    fs = scan({"app.py": 'PASSWORD = "SuperSecret5"\n'})
    assert not fs


def test_path_value_ignored(scan):
    fs = scan({"config.yml": 'PWD: "/app"\n'})
    assert not fs


def test_commented_placeholder_ignored(scan):
    fs = scan({"app.py": "# password: changeme\n# пароль: <your-password>\n"})
    assert not fs


def test_generic_key_ignored(scan):
    fs = scan({".env": "KEY=dev\n"})
    assert not fs


def test_env_placeholder_ignored(scan):
    fs = scan({".env": "PASSWORD=xxxx\nSECRET=test\n"})
    assert not fs
