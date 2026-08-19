"""tests/test_gs018_payment_abuse.py — positive/negative fixtures for GS018.

Covers the precision fixes: FLOAT_MONEY requires arithmetic after float(...),
PAYMENT_CONTEXT uses concrete payment nouns (no bare `order`/`transaction`),
and PROMO_REDEEM_NO_LOCK requires a standalone verb token + skips read-only
checks. TP cases (real rounding, real refund without state check, real promo
redeem without lock) must still fire.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs018_payment_abuse as gs018


@pytest.fixture()
def scan(tmp_path):
    def _scan(files):
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        ctx = AuditContext(project="test", path=tmp_path)
        return gs018.detect(ctx)
    return _scan


def _titles(fs):
    return [f["title"] for f in fs]


# ── FLOAT_MONEY ────────────────────────────────────────────────────────────

def test_float_money_arithmetic(scan):
    fs = scan({"calc.py": "# payment math\n"
                           "total = float(amount) * 0.9\n"})
    assert any("Float used for monetary value" in t for t in _titles(fs))


def test_float_money_conversion_only(scan):
    # bare conversion from API/JSON is parsing, not rounding arithmetic
    fs = scan({"prices.py": "# payment data\n"
                            "price = float(ticker['lastPrice'])\n"
                            "balance = float(data['balance'])\n"})
    assert not any("Float used for monetary value" in t for t in _titles(fs))


# ── Cancel/refund state validation ─────────────────────────────────────────

def test_refund_missing_state_check(scan):
    fs = scan({"orders.py": "def refund(order_id):\n"
                            "    order = get_order(order_id)\n"
                            "    process_refund(order)\n"})
    assert any("Cancel/refund without state validation" in t for t in _titles(fs))


def test_db_rollback_not_flagged(scan):
    # DB-driver rollback() carries a bare `transaction`, not a payment object
    fs = scan({"db.py": "def rollback(self):\n"
                        "    self.connection.rollback()\n"
                        "    self.transaction = None\n"})
    assert not any("Cancel/refund without state validation" in t for t in _titles(fs))


def test_order_by_not_flagged(scan):
    # SQL `ORDER BY` (bare `order`) and bare `transaction` are not payment nouns
    fs = scan({"query.py": "def rollback(tx):\n"
                           "    sql = 'SELECT * FROM txn ORDER BY id'\n"
                           "    tx.execute(sql)\n"
                           "    tx.transaction = None\n"})
    assert not any("Cancel/refund without state validation" in t for t in _titles(fs))


# ── Promo redeem without lock ──────────────────────────────────────────────

def test_promo_redeem_no_lock(scan):
    fs = scan({"promo.py": "def redeem_promo(code):\n"
                           "    promo = PromoCode.get(code)\n"
                           "    promo.used += 1\n"
                           "    promo.save()\n"})
    assert any("Promo code redeem without locking" in t for t in _titles(fs))


def test_promo_user_has_pending_not_flagged(scan):
    # `use` as a prefix of `user_...` is not a redeem verb
    fs = scan({"promo_dal.py": "def user_has_pending_payment_with_promo(user_id):\n"
                               "    return query.count() > 0\n"})
    assert not any("Promo code redeem without locking" in t for t in _titles(fs))


def test_promo_redeem_is_allowed_not_flagged(scan):
    # read-only check (redeem_is_allowed) is not a redeem action
    fs = scan({"promo.py": "def redeem_is_allowed(promo):\n"
                           "    return promo.remaining > 0\n"})
    assert not any("Promo code redeem without locking" in t for t in _titles(fs))
