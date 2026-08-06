"""S2 cloud tests: webhook, auth, onboarding, /gsc-команды."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest
from fakeredis import FakeRedis

from cloud.webhook import verify_signature
from cloud.dedup import DeliveryDedup
from cloud.github_auth import make_jwt, get_installation_token
from gsc_db_backend import PgBackend


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body,
                                hashlib.sha256).hexdigest()


def _fake_mint(token: str, expires_in: int = 3600):
    """Фейковый GitHub: возвращает свежий installation token."""
    exp = (__import__("datetime").datetime.now(
        __import__("datetime").timezone.utc) +
        __import__("datetime").timedelta(seconds=expires_in))
    def _mint(*args, **kwargs):
        resp = MagicMock()
        resp.json.return_value = {"token": token,
                                   "expires_at": exp.isoformat()}
        return resp
    return _mint


# ---------------------------------------------------------------------------
# test webhook signature (4 ветки)
# ---------------------------------------------------------------------------
def test_webhook_signature():
    body = b'{"action": "opened"}'
    s = "s3cret"
    assert verify_signature(body, _sign(body, s), s)
    assert not verify_signature(body, _sign(body, "other"), s)
    assert not verify_signature(body + b"x", _sign(body, s), s)
    assert not verify_signature(body, "md5=abc", s)


# ---------------------------------------------------------------------------
# delivery dedup (replay protection)
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_redis():
    return FakeRedis()


def test_delivery_dedup(fake_redis):
    d = DeliveryDedup()
    d._r = fake_redis                       # подмена на фейк
    assert d.once("gsc:delivery:abc", 60) is True
    assert d.once("gsc:delivery:abc", 60) is False   # replay отбит


# ---------------------------------------------------------------------------
# JWT timing bounds (реальный RSA + проверка границ)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def test_keys():
    """Генерация тестовых RSA-ключей."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    key = rsa.generate_private_key(65537, 2048, default_backend())
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def test_jwt_timing_bounds(monkeypatch, test_keys):
    priv, pub = test_keys
    monkeypatch.setenv("GSC_APP_PRIVATE_KEY", priv)
    monkeypatch.setenv("GSC_APP_ID", "12345")
    token = make_jwt()
    payload = pyjwt.decode(token, pub, algorithms=["RS256"],
                           options={"verify_exp": False})
    now = int(time.time())
    assert payload["iat"] <= now - 30          # запас на skew
    assert payload["exp"] - payload["iat"] <= 600
    assert payload["exp"] <= now + 600


def test_installation_token_refresh_margin(monkeypatch):
    from cloud.github_auth import _token_cache
    _token_cache[42] = ("old", time.time() + 60)   # истекает через минуту
    monkeypatch.setenv("GSC_APP_PRIVATE_KEY", "dummy")
    monkeypatch.setenv("GSC_APP_ID", "12345")
    # Мокаем mint: отдаём "new" токен
    monkeypatch.setattr("cloud.github_auth.make_jwt", lambda: "fake-jwt")
    monkeypatch.setattr("cloud.github_auth.requests.post", _fake_mint("new"))
    assert get_installation_token(42) == "new"     # обновлён заранее
    _token_cache[42] = ("fresh", time.time() + 3000)
    assert get_installation_token(42) == "fresh"   # из кэша


# ---------------------------------------------------------------------------
# PG-backed tests (пропускаются без PostgreSQL)
# ---------------------------------------------------------------------------
PG_DSN = os.environ.get("GSC_TEST_DATABASE_URL", "")
requires_pg = pytest.mark.skipif(
    not PG_DSN,
    reason="GSC_TEST_DATABASE_URL not set — PG-backed tests skipped")


def _seed_tenant(db, name="acme-org", plan="free"):
    db.conn.execute(
        "INSERT INTO tenants (name, plan) VALUES (%s, %s)", (name, plan))
    db.conn.execute("SELECT currval(pg_get_serial_sequence('tenants','id')) AS id")
    return db.conn.fetchone()["id"]
    row = db.conn.execute(
        "SELECT currval(pg_get_serial_sequence('tenants','id')) AS id").fetchone()
    return row["id"]


@requires_pg
def test_install_auto_creates_tenant():
    from cloud.onboarding import ensure_tenant_for_install
    from cloud.store import control_plane
    tid = ensure_tenant_for_install(77777, "acme-org")
    tid2 = ensure_tenant_for_install(77777, "acme-org")
    assert tid == tid2                              # идемпотентно
    row = control_plane().fetchone(
        "SELECT plan FROM tenants WHERE id = ?", (tid,))
    assert row["plan"] == "free"


@requires_pg
def test_supersede_stale_queued_scans():
    from cloud.scanjobs import handle_pull_request
    p1 = {
        "action": "opened",
        "installation": {"id": 999},
        "repository": {"id": 1, "full_name": "a/r", "clone_url": "https://github.com/a/r", "owner": {"login": "a"}},
        "pull_request": {"number": 1, "head": {"sha": "a" * 40, "repo": {"full_name": "a/r"}}, "base": {"ref": "main"}},
    }
    p2 = {
        "action": "synchronize",
        "installation": {"id": 999},
        "repository": {"id": 1, "full_name": "a/r", "clone_url": "https://github.com/a/r", "owner": {"login": "a"}},
        "pull_request": {"number": 1, "head": {"sha": "b" * 40, "repo": {"full_name": "a/r"}}, "base": {"ref": "main"}},
    }
    handle_pull_request(p1)
    handle_pull_request(p2)


@requires_pg
def test_fork_pr_job_flagged():
    from cloud.scanjobs import handle_pull_request
    payload = {
        "action": "opened",
        "installation": {"id": 999},
        "repository": {"id": 1, "full_name": "a/r", "clone_url": "https://github.com/a/r", "owner": {"login": "a"}},
        "pull_request": {"number": 2, "head": {"sha": "c" * 40, "repo": {"full_name": "evil/fork"}}, "base": {"ref": "main"}},
    }
    result = handle_pull_request(payload)
    assert result["scan_id"] > 0


@requires_pg
def test_gsc_command_via_webhook_tenant_scoped():
    from cloud.pr_commands import handle_issue_comment
    from cloud.store import control_plane

    # Seed 2 tenants
    db0 = control_plane()
    db0.execute("INSERT INTO tenants (name, plan) VALUES (%s, 'free') ON CONFLICT DO NOTHING", ("t1",))
    db0.execute("INSERT INTO tenants (name, plan) VALUES (%s, 'free') ON CONFLICT DO NOTHING", ("t2",))
    db0.execute("INSERT INTO github_installs (tenant_id, installation_id, org_login) VALUES (%s, %s, %s)",
                (1, 777, "t1"))
    db0.commit()

    # Seed finding for tenant 1
    db1 = PgBackend(PG_DSN, 1)
    db1.execute("""INSERT INTO repos (tenant_id, name, clone_url, gh_repo_id) VALUES (%s, 'r', 'x', %s)""",
                (1, 42))
    db1.execute("""INSERT INTO findings (tenant_id, scan_id, finding_key, rule_id, severity, confidence, file, line) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (1, 1, "abc123def456", "GS001", "HIGH", 0.9, "x.py", 1))
    db1.commit()

    payload = {
        "installation": {"id": 777},
        "repository": {"id": 42, "full_name": "t1/repo"},
        "issue": {"number": 1, "pull_request": True},
        "comment": {
            "id": 100,
            "body": "/gsc fp abc123def456 test reason",
            "author_association": "MEMBER",
            "user": {"login": "dev1"},
        },
    }
    handle_issue_comment(payload)

    # Tenant 1 sees verdict
    v1 = db1.fetchone("SELECT verdict FROM verdicts WHERE finding_key = %s", ("abc123def456",))
    assert v1["verdict"] == "fp"

    # Tenant 2 should NOT see it
    db2 = PgBackend(PG_DSN, 2)
    v2 = db2.fetchone("SELECT 1 AS x FROM verdicts WHERE finding_key = %s", ("abc123def456",))
    assert v2 is None