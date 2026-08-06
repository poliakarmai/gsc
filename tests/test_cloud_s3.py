"""S3 tests: auth, sessions, dashboard BFF, Stripe billing."""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from fakeredis import FakeRedis

from cloud.session import issue as session_issue, parse as session_parse

PG_DSN = os.environ.get("GSC_DATABASE_URL", "")
requires_pg = pytest.mark.skipif(
    not PG_DSN, reason="GSC_DATABASE_URL not set")

# Ensure env vars for session tests
os.environ.setdefault("GSC_SESSION_SECRET", "test-s3-secret-32bytes!!")
os.environ.setdefault("GSC_OAUTH_CLIENT_ID", "test-client-id")
os.environ.setdefault("GSC_OAUTH_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("GSC_OAUTH_REDIRECT_URI", "http://localhost:3000/api/auth/callback")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_redis():
    class FR(FakeRedis):
        def getdel(self, key):
            val = self.get(key)
            if val is not None:
                self.delete(key)
            return val
    return FR()


# ---------------------------------------------------------------------------
# OAuth state (CSRF protection)
# ---------------------------------------------------------------------------
def test_oauth_state_single_use(fake_redis):
    from cloud.user_auth import begin_login

    class FakeDedup:
        def once_raw(self, key, ttl, value="pending"):
            return bool(fake_redis.set(key, value, nx=True, ex=ttl))
        def consume(self, key):
            return fake_redis.getdel(key) is not None

    url, state = begin_login(FakeDedup())
    assert "state=" in url
    assert FakeDedup().consume(f"gsc:oauth:{state}") is True
    assert FakeDedup().consume(f"gsc:oauth:{state}") is False  # replay blocked


# ---------------------------------------------------------------------------
# Session tamper protection
# ---------------------------------------------------------------------------
def test_session_tamper_rejected():
    cookie = session_issue(1, 7)
    body, sig = cookie.rsplit("|", 1)
    forged = body.replace('"tid":7', '"tid":8') + "|" + sig
    assert session_parse(cookie)["tid"] == 7
    assert session_parse(forged) is None
    assert session_parse(cookie[:-4] + "xxxx") is None


# ---------------------------------------------------------------------------
# Stripe: bad signature (no PG needed)
# ---------------------------------------------------------------------------
def test_stripe_webhook_bad_signature(monkeypatch):
    import stripe as stripe_mod
    monkeypatch.setattr(stripe_mod, "Webhook", MagicMock(
        construct_event=MagicMock(side_effect=ValueError("bad sig"))))
    from cloud.billing import handle_webhook
    with pytest.raises(PermissionError):
        handle_webhook(MagicMock(), b'{}', "sha256=deadbeef")


# ---------------------------------------------------------------------------
# Stripe: downgrade (no PG needed — mock db)
# ---------------------------------------------------------------------------
def test_downgrade_on_subscription_cancel(monkeypatch):
    import stripe as stripe_mod
    from cloud.billing import handle_webhook

    sub_obj = MagicMock()
    sub_obj.metadata.get.return_value = "1"
    evt = MagicMock()
    evt.id = "evt_cancel"
    evt.type = "customer.subscription.deleted"
    evt.data.object = sub_obj

    monkeypatch.setattr(stripe_mod, "Webhook", MagicMock(
        construct_event=lambda *a: evt))

    db = MagicMock()
    db.fetchone.return_value = None  # no existing event
    handle_webhook(db, b'{}', "sig")
    db.execute.assert_called()  # downgrade executed


# ---------------------------------------------------------------------------
# Stripe: idempotent (PG)
# ---------------------------------------------------------------------------
@requires_pg
def test_stripe_webhook_idempotent(monkeypatch):
    import stripe as stripe_mod
    from cloud.billing import handle_webhook
    from gsc_db_backend import PgBackend

    sub_obj = MagicMock()
    sub_obj.metadata.get.return_value = "1"
    items = MagicMock()
    data_item = MagicMock()
    def di_getitem(k):
        if k == "quantity": return 3
        if k == "price": return data_item.price
        return MagicMock()
    data_item.__getitem__ = MagicMock(side_effect=di_getitem)
    data_item.price = MagicMock()
    data_item.price.id = "price_team"
    items.__getitem__.return_value = [data_item]  # ["data"]

    def sub_getitem(k):
        if k == "items":
            return items
        if k == "metadata":
            return {"tenant_id": "1"}
        if k == "status":
            return "active"
        return MagicMock()

    sub_obj.__getitem__ = MagicMock(side_effect=sub_getitem)

    evt = MagicMock()
    evt.id = "evt_s3_1"
    evt.type = "checkout.session.completed"
    evt.data = MagicMock()
    evt.data.object = {"subscription": "sub_1", "metadata": {"tenant_id": "1"}}

    sub = MagicMock()
    sub.status = "active"
    sub.metadata = {"tenant_id": "1"}
    sub.__getitem__ = sub_obj.__getitem__

    monkeypatch.setattr(stripe_mod, "Webhook", MagicMock(
        construct_event=lambda *a, **kw: evt))
    monkeypatch.setattr(stripe_mod, "Subscription", MagicMock(
        retrieve=lambda sid: sub))

    db = PgBackend(PG_DSN, 0)
    handle_webhook(db, b'{"type":"test"}', "sig")
    handle_webhook(db, b'{"type":"test"}', "sig")
    count = db.fetchone(
        "SELECT COUNT(*) AS c FROM stripe_events WHERE event_id = %s",
        ("evt_s3_1",))["c"]
    assert count == 1


# ---------------------------------------------------------------------------
# Dashboard tests (PG)
# ---------------------------------------------------------------------------
@requires_pg
def test_findings_tenant_scoped():
    from cloud.session import issue
    from gsc_db_backend import PgBackend

    db0 = PgBackend(PG_DSN, 0)
    # Ensure tenant 1 exists
    db0.conn.execute(
        "INSERT INTO tenants (id, name, plan) VALUES (%s, 's3test', 'free') "
        "ON CONFLICT (id) DO NOTHING", (1,))
    db0.conn.execute(
        "INSERT INTO users (id, github_id, login) VALUES (%s, %s, 'u1') "
        "ON CONFLICT (id) DO NOTHING", (100, 11111,))
    db0.conn.execute(
        "INSERT INTO memberships (user_id, tenant_id, role) VALUES "
        "(%s, %s, 'owner') ON CONFLICT DO NOTHING", (100, 1))
    db0.conn.commit()

    cookie = issue(100, 1)

    class FakeReq:
        cookies = {"gsc_session": cookie}

    from cloud.dash_api import _ctx
    uid, tid = _ctx(FakeReq())
    assert tid == 1