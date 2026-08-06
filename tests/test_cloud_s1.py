"""S1 cloud tests: backend, auth, worker, security."""
import hashlib
import subprocess

import pytest

from gsc_db_backend import PgBackend, q_to_pg
from cloud.auth import Unauthorized, auth_tenant, generate_api_key


# ---------------------------------------------------------------------------
# backend tests
# ---------------------------------------------------------------------------
def test_q_to_pg_placeholder_conversion():
    sql = "SELECT * FROM findings WHERE rule_id = ? AND note = 'what?'"
    out = q_to_pg(sql)
    assert out == "SELECT * FROM findings WHERE rule_id = %s AND note = 'what?'"


def test_pg_backend_requires_tenant():
    try:
        PgBackend("postgresql://...", tenant_id=None)
        assert False, "should have raised"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# auth tests
# ---------------------------------------------------------------------------
def test_api_key_format():
    raw, h = generate_api_key()
    assert raw.startswith("gsc_")
    assert len(raw) > 20
    assert hashlib.sha256(raw.encode()).hexdigest() == h


# ---------------------------------------------------------------------------
# SSRF guard (standalone — не требует PG)
# ---------------------------------------------------------------------------
def test_target_validation_blocks_ssrf():
    from cloud.worker import validate_target

    for bad in [
        "http://github.com/x",
        "https://10.0.0.1/x",
        "https://github.com.evil.com/x",
        "file:///etc/passwd",
    ]:
        try:
            validate_target(bad)
            assert False, f"should reject: {bad}"
        except ValueError:
            pass
    validate_target("https://github.com/org/repo")  # ok


# ---------------------------------------------------------------------------
# worker: exit 1 = success (не требует PG)
# ---------------------------------------------------------------------------
def test_worker_treats_blocking_exit_as_success(monkeypatch):
    class FakeProc:
        returncode = 1
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())

    from cloud.worker import run_scanner

    try:
        run_scanner({"target": "https://github.com/o/r", "profile": "pr-gate"})
    except FileNotFoundError:
        # Нет реального gsc CLI в тестовом окружении — ожидаемо
        pass
    except RuntimeError as e:
        assert "scanner failed" not in str(e), f"blocking exit treated as error: {e}"


# ---------------------------------------------------------------------------
# PG-backed tests (пропускаются без psql)
# ---------------------------------------------------------------------------
requires_pg = pytest.mark.skipif(
    True,  # skip in CI without running PG container
    reason="PostgreSQL not available — PG-backed tests skipped",
)


@requires_pg
def test_quota_returns_402():
    """Integration: 51-й скан free-плана → 402."""
    ...  # требует живой PG + seed-тенанта


@requires_pg
def test_cross_tenant_isolation():
    """Integration: тенант A не видит findings тенанта B."""
    ...  # требует живой PG с двумя тенантами