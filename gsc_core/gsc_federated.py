#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Federated Self-Learning v1.0 (v0.30).

Cross-tenant learning without code leakage. Tenants anonymously share
TP/FP counts per rule_id. Central server aggregates global weights.
Tenants adjust confidence + deactivate globally noisy rules.

Privacy: ONLY {tenant_hash, rule_id, tp, fp} are transmitted.
NEVER: code, snippets, file paths, finding_keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import random
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HTTP_TIMEOUT = 30
# Audit #2 §3.1: pseudonym rotation period (days). Submissions older than this
# are not linkable via tenant_hash; self-learning uses a sliding window anyway.
ROTATION_PERIOD_DAYS = 7
# Audit #2 §3.2: privacy budget thresholds (sum of per-submit epsilon).
BUDGET_WARN_EPSILON = 5.0
BUDGET_STOP_EPSILON = 10.0

# Self-poisoning defence (EVOMAL): federated weights are soft signals — never
# trusted blindly. Quorum + sanity bounds reject poisoned/implausible weights
# before they can deactivate a local detector or boost a malicious one.
MIN_FED_TENANTS = 3       # independent tenants required to trust a weight (Sybil)
MIN_FED_VERDICTS = 20     # minimum verdict volume for a weight to be considered


def _base_rule(rule_id: str) -> str:
    """GS025-permissive_cors → GS025; GS030-PYSEC-x → GS030."""
    return rule_id.split("-")[0]


# ── Differential Privacy ───────────────────────────────────
def add_laplace_noise(count: int, epsilon: float) -> int:
    """Laplace noise for DP. sensitivity=1."""
    if epsilon <= 0:
        return count
    scale = 1.0 / epsilon
    u = random.random() - 0.5
    noise = -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
    return max(0, int(count + noise))


# ── Local metric collection ────────────────────────────────
def collect_local_metrics(db, min_verdicts: int = 3) -> Dict[str, Dict[str, int]]:
    """Collect local TP/FP by base rule_id from feedback. No code/paths."""
    rows = db.conn.execute("""
        SELECT f.rule_id AS rule_id,
               SUM(CASE WHEN fb.verdict IN ('tp','fixed') THEN 1 ELSE 0 END) AS tp,
               SUM(CASE WHEN fb.verdict = 'fp' THEN 1 ELSE 0 END) AS fp
        FROM feedback fb
        JOIN findings f ON f.finding_key = fb.finding_key
        GROUP BY f.rule_id
    """).fetchall()

    metrics: Dict[str, Dict[str, int]] = {}
    for r in rows:
        base = _base_rule(r["rule_id"])
        m = metrics.setdefault(base, {"tp": 0, "fp": 0})
        m["tp"] += r["tp"] or 0
        m["fp"] += r["fp"] or 0

    return {rid: m for rid, m in metrics.items()
            if (m["tp"] + m["fp"]) >= min_verdicts}


def _sanitize_weight(rule_id: str, data: object) -> Optional[tuple]:
    """Validate a fetched federated weight (self-poisoning defence).

    Rejects non-dict payloads, ``tp_rate`` outside ``[0, 1]``, NaN/inf, verdict
    volume below ``MIN_FED_VERDICTS``, or a tenant quorum below
    ``MIN_FED_TENANTS``. Returns ``(tp_rate, verdicts)`` on success, ``None``
    to drop the entry.
    """
    if not isinstance(data, dict):
        return None
    try:
        tp_rate = float(data.get("tp_rate", 0.0))
        verdicts = int(data.get("verdicts", 0))
        tenants = int(data.get("tenants", 0))
    except (TypeError, ValueError):
        return None
    if math.isnan(tp_rate) or math.isinf(tp_rate):
        return None
    if not (0.0 <= tp_rate <= 1.0):
        return None
    if verdicts < MIN_FED_VERDICTS:
        return None
    if tenants < MIN_FED_TENANTS:
        return None
    return (tp_rate, verdicts)


# ── Federated Client ───────────────────────────────────────
class FederatedClient:
    def __init__(self, db, server_url: str, api_key: str,
                 enabled: bool = True, epsilon: float = 1.0,
                 min_verdicts: int = 3, hmac_key: str = ""):
        self.db = db
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.enabled = enabled
        self.epsilon = epsilon
        self.min_verdicts = min_verdicts
        # Audit #2 §3.4: payload integrity via HMAC (MITM protection).
        self.hmac_key = hmac_key or os.environ.get("GSC_FEDERATED_HMAC_KEY", "")

    def _tenant_hash(self) -> str:
        # Audit #2 §3.1: rotate the pseudonym by epoch so submissions older than
        # ROTATION_PERIOD_DAYS are not linkable. Losing long-term history is
        # acceptable — self-learning operates on a sliding window.
        seed = getattr(self.db, "tenant_id", "local")
        epoch = int(time.time()) // (ROTATION_PERIOD_DAYS * 86400)
        return hashlib.sha256(f"gsc-tenant:{seed}:{epoch}".encode()).hexdigest()[:16]

    def _epsilon_spent(self) -> float:
        """Sum of per-submit epsilon recorded in federated_log (budget accounting)."""
        try:
            row = self.db.conn.execute(
                "SELECT SUM(CAST(detail AS REAL)) AS s FROM federated_log "
                "WHERE action = 'budget_spent'"
            ).fetchone()
            return float(row["s"] or 0.0)
        except Exception:
            return 0.0

    def _check_budget(self, spent: float) -> str:
        """Audit #2 §3.2: soft warn (ε>5) → log+flag; hard stop (ε>10) → disable."""
        if spent > BUDGET_STOP_EPSILON:
            return "stop"
        if spent > BUDGET_WARN_EPSILON:
            return "warn"
        return "ok"

    def _sign(self, body: bytes) -> str:
        """HMAC-SHA256 hex signature of the request body ("" if no key configured)."""
        if not self.hmac_key:
            return ""
        return hmac.new(self.hmac_key.encode(), body, hashlib.sha256).hexdigest()

    def _request(self, path: str, body: bytes, method: str = "POST"):
        """TLS-enforced signed request. Rejects non-HTTPS (audit #2 §3.4, MITM)."""
        if not self.server_url.startswith("https://"):
            raise ValueError("federated server must be HTTPS (MITM protection)")
        import urllib.request as request
        ctx = ssl.create_default_context()  # verify server certificate
        req = request.Request(f"{self.server_url}{path}", data=body or None, method=method)
        req.add_header("x-api-key", self.api_key)
        req.add_header("Content-Type", "application/json")
        if body and self.hmac_key:
            req.add_header("x-signature", self._sign(body))
        return request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx)

    def _log(self, action: str, detail: str):
        self.db.conn.execute(
            "INSERT OR IGNORE INTO federated_log (action, detail) VALUES (?, ?)",
            (action, detail[:200]))
        self.db.conn.commit()

    # ── Submit local metrics ────────────────────────────
    def submit(self) -> bool:
        if not self.enabled:
            return False
        metrics = collect_local_metrics(self.db, self.min_verdicts)
        if not metrics:
            return False
        # Budget accounting (audit #2 §3.2): soft warn (ε>5) / hard stop (ε>10).
        if self.epsilon > 0:
            spent = self._epsilon_spent()
            state = self._check_budget(spent)
            if state == "stop":
                self._log("budget", f"epsilon_spent={spent:.2f} STOP (>{BUDGET_STOP_EPSILON})")
                return False
            if state == "warn":
                self._log("budget", f"epsilon_spent={spent:.2f} WARN (>{BUDGET_WARN_EPSILON})")
        # DP noise
        if self.epsilon > 0:
            for rid in metrics:
                metrics[rid]["tp"] = add_laplace_noise(metrics[rid]["tp"], self.epsilon)
                metrics[rid]["fp"] = add_laplace_noise(metrics[rid]["fp"], self.epsilon)
        payload = {"tenant_hash": self._tenant_hash(), "metrics": metrics}
        try:
            body = json.dumps(payload).encode()
            with self._request("/api/v1/federated/submit", body) as resp:
                ok = resp.status == 200
            if ok and self.epsilon > 0:
                self._log("budget_spent", f"{self.epsilon}")
            self._log("submit", f"rules={len(metrics)} ok={ok}")
            return ok
        except Exception as e:
            self._log("submit", f"error={e}")
            return False

    # ── Fetch global weights ────────────────────────────
    def fetch_weights(self) -> Dict[str, dict]:
        if not self.enabled:
            return {}
        try:
            with self._request("/api/v1/federated/weights", b"", method="GET") as resp:
                weights = json.loads(resp.read())
        except Exception as e:
            self._log("fetch", f"error={e}")
            return {}

        for rule_id, data in weights.items():
            clean = _sanitize_weight(rule_id, data)
            if clean is None:
                self._log("fetch", f"reject={rule_id}")
                continue
            tp_rate, verdicts = clean
            self.db.conn.execute("""
                INSERT OR REPLACE INTO federated_global_weights
                (rule_id, global_tp_rate, global_verdicts, updated_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (rule_id, tp_rate, verdicts))
        self.db.conn.commit()
        self._log("fetch", f"rules={len(weights)}")
        return weights

    # ── Local accessor ──────────────────────────────────
    def get_global_tp_rate(self, rule_id: str) -> Optional[float]:
        base = _base_rule(rule_id)
        row = self.db.conn.execute("""
            SELECT global_tp_rate, global_verdicts
            FROM federated_global_weights WHERE rule_id = ?
        """, (base,)).fetchone()
        if row and row["global_verdicts"] >= 20:
            return row["global_tp_rate"]
        return None


# ── Confidence adjustment ──────────────────────────────────
def adjust_confidence(finding: dict, client: FederatedClient) -> dict:
    global_tp = client.get_global_tp_rate(finding.get("rule_id", ""))
    if global_tp is None:
        return finding

    conf = finding.get("confidence", 0.0)
    meta = finding.setdefault("metadata", {})

    if global_tp < 0.50:
        penalty = (0.50 - global_tp) * 0.30
        finding["confidence"] = max(0.05, conf - penalty)
        meta["federated_adjusted"] = "penalty"
        meta["global_tp_rate"] = round(global_tp, 3)
    elif global_tp > 0.85:
        boost = (global_tp - 0.85) * 0.20
        finding["confidence"] = min(0.99, conf + boost)
        meta["federated_adjusted"] = "boost"
        meta["global_tp_rate"] = round(global_tp, 3)
    return finding


# ── Global auto-deactivate ─────────────────────────────────
def auto_deactivate_global(db, client: FederatedClient,
                           tp_threshold: float = 0.30,
                           min_verdicts: int = 30) -> List[str]:
    rows = db.conn.execute("""
        SELECT rule_id, global_tp_rate, global_verdicts
        FROM federated_global_weights
        WHERE global_tp_rate < ? AND global_verdicts >= ?
    """, (tp_threshold, min_verdicts)).fetchall()

    deactivated = []
    for r in rows:
        # Self-poisoning defence: federated data must never deactivate a rule
        # that has local TP evidence. Local observations win over fed signals.
        local_tp = db.conn.execute("""
            SELECT COUNT(*) AS n
            FROM feedback fb JOIN findings f ON f.finding_key = fb.finding_key
            WHERE f.rule_id LIKE ? AND fb.verdict IN ('tp','fixed')
        """, (r["rule_id"] + "%",)).fetchone()["n"]
        if local_tp > 0:
            continue
        db.conn.execute("""
            INSERT OR IGNORE INTO federated_deactivated (rule_id, reason)
            VALUES (?, ?)
        """, (r["rule_id"],
              f"global_tp_rate={r['global_tp_rate']:.2f}@{r['global_verdicts']}verdicts"))
        # fp_log: structured federated deactivation event (schema v33)
        db.record_fp(
            rule_id=r["rule_id"],
            reason="auto_deactivated",
            comment=f"global_tp_rate={r['global_tp_rate']:.2f}@{r['global_verdicts']}verdicts",
            action_taken="federated_deactivated",
            source="federated",
        )
        deactivated.append(r["rule_id"])
    if deactivated:
        db.conn.commit()
    return deactivated


def is_globally_deactivated(db, rule_id: str) -> bool:
    base = _base_rule(rule_id)
    row = db.conn.execute(
        "SELECT 1 FROM federated_deactivated WHERE rule_id = ?", (base,)).fetchone()
    return row is not None


# ── Cold start ─────────────────────────────────────────────
def cold_start_adjust(finding: dict, client: FederatedClient,
                      local_verdicts: int, threshold: int = 5) -> dict:
    if local_verdicts < threshold:
        return adjust_confidence(finding, client)
    return finding


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Federated Learning")
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("status", help="Show federated status")
    sub.add_parser("submit", help="Submit local metrics")
    sub.add_parser("fetch", help="Fetch global weights")
    wp = sub.add_parser("weights", help="Show global weight for a rule")
    wp.add_argument("rule", help="rule_id")

    args = p.parse_args()

    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_core.gsc_db import GSCDatabase
    db = GSCDatabase()
    db.__enter__()

    # Dummy client for local ops
    client = FederatedClient(db, "http://localhost", "key", enabled=True)

    if args.action == "status":
        w = db.conn.execute("SELECT COUNT(*) AS n FROM federated_global_weights").fetchone()
        d = db.conn.execute("SELECT COUNT(*) AS n FROM federated_deactivated").fetchone()
        print(f"Global weights cached: {w['n']} rules")
        print(f"Globally deactivated:  {d['n']} rules")
        print(f"Tenant hash: {client._tenant_hash()}")

    elif args.action == "submit":
        ok = client.submit()
        print(f"Submit: {'OK' if ok else 'FAILED'}")

    elif args.action == "fetch":
        weights = client.fetch_weights()
        print(f"Fetched {len(weights)} global weights")

    elif args.action == "weights":
        rate = client.get_global_tp_rate(args.rule)
        if rate is not None:
            print(f"{args.rule}: global_tp_rate={rate:.3f}")
        else:
            print(f"No global data for {args.rule}")

    db.close()


if __name__ == "__main__":
    main()
