#!/usr/bin/env python3
"""gsc-cloud manage: tenants, api keys, quota.

Только для оператора. Raw-ключ печатается ОДИН раз.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloud.auth import generate_api_key
from cloud.store import control_plane

PLANS = {
    "free": (50, 0),
    "team": (500, 200),
    "business": (5000, 1000),
}


def cmd_create_tenant(args) -> int:
    scan_limit, llm_budget = PLANS[args.plan]
    db = control_plane()
    db.execute(
        "INSERT INTO tenants (name, plan, scan_limit_month, llm_budget_month) "
        "VALUES (?, ?, ?, ?)",
        (args.name, args.plan, scan_limit, llm_budget))
    tenant_id = db.fetchone(
        "SELECT currval(pg_get_serial_sequence('tenants','id')) AS id")["id"]
    raw, key_hash = generate_api_key()
    db.execute("INSERT INTO api_keys (tenant_id, key_hash, prefix) "
               "VALUES (?, ?, ?)", (tenant_id, key_hash, raw[:12]))
    db.commit()
    print(f"tenant_id: {tenant_id}")
    print(f"api_key (shown ONCE): {raw}")
    return 0


def cmd_list_keys(args) -> int:
    db = control_plane()
    rows = db.query("""
        SELECT k.id, k.tenant_id, t.name, k.prefix, k.created_at, k.revoked_at
        FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
        ORDER BY k.id
    """)
    for r in rows:
        state = "REVOKED" if r["revoked_at"] else "active"
        print(f"#{r['id']} tenant={r['tenant_id']} ({r['name']}) "
              f"{r['prefix']}… [{state}] {r['created_at']}")
    return 0


def cmd_revoke(args) -> int:
    db = control_plane()
    db.execute("UPDATE api_keys SET revoked_at = now() WHERE id = ?",
               (args.key_id,))
    db.commit()
    print(f"key #{args.key_id} revoked")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(prog="gsc-cloud")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("create-tenant")
    pc.add_argument("--name", required=True)
    pc.add_argument("--plan", choices=PLANS, default="free")
    pc.set_defaults(func=cmd_create_tenant)

    pl = sub.add_parser("list-keys")
    pl.set_defaults(func=cmd_list_keys)

    pr = sub.add_parser("revoke-key")
    pr.add_argument("key_id", type=int)
    pr.set_defaults(func=cmd_revoke)

    args = p.parse_args()
    sys.exit(args.func(args))