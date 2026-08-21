"""tests/test_gs044_trading_bots.py — positive/negative fixtures for GS044."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs044_trading_bots as g


def _run(tmp_path: Path) -> list:
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _titles(findings):
    return {f["title"] for f in findings}


# ── Positives (must fire) ───────────────────────────────────────────────────


def test_timestamp_as_nonce_detected(tmp_path):
    (tmp_path / "bot.py").write_text(
        "import time, ccxt\n"
        "exchange = ccxt.binance()\n"
        "nonce = int(time.time() * 1000)\n"
        "exchange.create_order('BTC/USDT', 'limit', 'buy', 1, 100)\n"
    )
    assert "Timestamp used as request nonce (replayable)" in _titles(_run(tmp_path))


def test_hardcoded_nonce_detected(tmp_path):
    (tmp_path / "bot.py").write_text(
        "exchange = ccxt.binance()\n"
        "nonce = 1612345678\n"
        "exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
    )
    assert "Hardcoded nonce (replay attack)" in _titles(_run(tmp_path))


def test_recvwindow_zero_detected(tmp_path):
    (tmp_path / "bot.py").write_text(
        "exchange = ccxt.bybit()\n"
        "recvWindow = 0\n"
        "exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
    )
    assert "recvWindow disabled (replay window open)" in _titles(_run(tmp_path))


def test_unvalidated_qty_detected(tmp_path):
    (tmp_path / "bot.py").write_text(
        "exchange = ccxt.binance()\n"
        "qty = float(input('amount: '))\n"
        "exchange.create_order('BTC/USDT', 'market', 'buy', qty)\n"
    )
    assert "Order size/price from unvalidated external input" in _titles(_run(tmp_path))


def test_unauthenticated_endpoint_detected(tmp_path):
    (tmp_path / "web.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "exchange = ccxt.binance()\n"
        "@app.route('/trade')\n"
        "def trade():\n"
        "    exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
        "    return 'ok'\n"
    )
    assert "Unauthenticated trading endpoint" in _titles(_run(tmp_path))


def test_check_then_act_race_detected(tmp_path):
    (tmp_path / "bot.py").write_text(
        "class Bot:\n"
        "    def run(self, exchange):\n"
        "        positions = self.get_positions()\n"
        "        if 'BTC/USDT' not in positions:\n"
        "            exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
    )
    assert "Non-atomic check-then-act on position/balance" in _titles(_run(tmp_path))


# ── Negatives (must NOT fire) ───────────────────────────────────────────────


def test_clean_code_not_flagged(tmp_path):
    (tmp_path / "clean.py").write_text("x = 42\nprint('hello')\n")
    assert _run(tmp_path) == []


def test_non_trading_nonce_not_flagged(tmp_path):
    # nonce in a non-trading (ECDSA) context must not fire
    (tmp_path / "crypto.py").write_text(
        "import secrets\n"
        "nonce = secrets.randbelow(2**256)\n"
    )
    assert _run(tmp_path) == []


def test_ecommerce_create_order_not_flagged(tmp_path):
    # create_order without trading context is not a trading bot
    (tmp_path / "shop.py").write_text(
        "def create_order(customer_id, items):\n"
        "    return {'id': customer_id, 'items': items}\n"
    )
    assert _run(tmp_path) == []


def test_validated_qty_not_flagged(tmp_path):
    (tmp_path / "bot.py").write_text(
        "exchange = ccxt.binance()\n"
        "qty = max(0.001, min(10.0, float(config['qty'])))\n"
        "exchange.create_order('BTC/USDT', 'market', 'buy', qty)\n"
    )
    assert "Order size/price from unvalidated external input" not in _titles(_run(tmp_path))


def test_authenticated_endpoint_not_flagged(tmp_path):
    (tmp_path / "web.py").write_text(
        "from flask import Flask\n"
        "from flask_login import login_required\n"
        "app = Flask(__name__)\n"
        "exchange = ccxt.binance()\n"
        "@app.route('/trade')\n"
        "@login_required\n"
        "def trade():\n"
        "    exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
        "    return 'ok'\n"
    )
    assert "Unauthenticated trading endpoint" not in _titles(_run(tmp_path))


def test_locked_race_not_flagged(tmp_path):
    (tmp_path / "bot.py").write_text(
        "import threading\n"
        "class Bot:\n"
        "    def __init__(self):\n"
        "        self.lock = threading.Lock()\n"
        "    def run(self, exchange):\n"
        "        with self.lock:\n"
        "            positions = self.get_positions()\n"
        "            if 'BTC/USDT' not in positions:\n"
        "                exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
    )
    assert "Non-atomic check-then-act on position/balance" not in _titles(_run(tmp_path))


def test_test_path_excluded(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "bot.py").write_text(
        "exchange = ccxt.binance()\n"
        "nonce = int(time.time())\n"
        "exchange.create_order('BTC/USDT', 'market', 'buy', 1)\n"
    )
    assert _run(tmp_path) == []


def test_abstract_method_not_flagged(tmp_path):
    # place_order / get_positions as abstract interface methods are NOT a race
    (tmp_path / "adapter.py").write_text(
        "from abc import ABC, abstractmethod\n"
        "class ExchangeAdapter(ABC):\n"
        "    @abstractmethod\n"
        "    def get_positions(self):\n"
        "        ...\n"
        "    @abstractmethod\n"
        "    def place_order(self, symbol, side, qty):\n"
        "        ...\n"
    )
    assert _run(tmp_path) == []


def test_docstring_example_not_flagged(tmp_path):
    # order calls inside a docstring are documentation, not code
    (tmp_path / "paper_api.py").write_text(
        '"""Paper trading API.\n'
        '\n'
        'Usage:\n'
        "    px = PaperExchange()\n"
        "    px.place_order('BTCUSDT', 'Buy', 'Market', 0.01)\n"
        '"""\n'
    )
    assert _run(tmp_path) == []


def test_import_not_flagged(tmp_path):
    # importing a place_order function is not an order placement
    (tmp_path / "bot.py").write_text(
        "from .api import place_order as _close_order\n"
        "positions = get_positions()\n"
    )
    assert _run(tmp_path) == []
