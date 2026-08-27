# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Stripe billing (S3): seat-based подписки + webhook.

Планы (за пользователя в месяц):
  free     — без Stripe, лимиты в коде
  team     — $29, 500 сканов/мес, LLM включён
  business — $49, 5000 сканов/мес, LLM расширенный
"""
from __future__ import annotations

import os

import stripe

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")

PLANS = {
    "free": {"price_id": None, "scan_limit": 50, "llm_budget": 0},
    "team": {"price_id": os.environ.get("STRIPE_PRICE_TEAM"),
             "scan_limit": 500, "llm_budget": 200},
    "business": {"price_id": os.environ.get("STRIPE_PRICE_BUSINESS"),
                 "scan_limit": 5000, "llm_budget": 1000},
}


def create_checkout(db, tenant_id: int, plan: str, seats: int,
                    success_url: str, cancel_url: str) -> str:
    if plan not in ("team", "business"):
        raise ValueError("free plan does not use Stripe")
    if seats < 1 or seats > 500:
        raise ValueError("seats out of range")
    tenant = db.fetchone("SELECT * FROM tenants WHERE id = ?",
                         (tenant_id,))
    customer_id = tenant["stripe_customer_id"]
    if not customer_id:
        customer = stripe.Customer.create(
            name=tenant["name"],
            metadata={"tenant_id": str(tenant_id)})
        customer_id = customer.id
        db.execute("UPDATE tenants SET stripe_customer_id = ? WHERE id = ?",
                   (customer_id, tenant_id))
    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": PLANS[plan]["price_id"], "quantity": seats}],
        metadata={"tenant_id": str(tenant_id), "plan": plan},
        subscription_data={"metadata": {"tenant_id": str(tenant_id)}},
        success_url=success_url, cancel_url=cancel_url)
    return session.url


def handle_webhook(db, payload: bytes, sig_header: str) -> None:
    secret = os.environ["STRIPE_WEBHOOK_SECRET"]
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise PermissionError("invalid stripe signature")

    if db.fetchone("SELECT 1 FROM stripe_events WHERE event_id = ?",
                   (event.id,)):
        return
    db.execute("INSERT INTO stripe_events (event_id, event_type, payload) "
               "VALUES (?, ?, ?)",
               (event.id, event.type, payload.decode()[:10000]))

    if event.type in ("checkout.session.completed",
                      "customer.subscription.updated"):
        _sync_subscription(db, event)
    elif event.type == "customer.subscription.deleted":
        _downgrade_to_free(db, event)
    db.commit()


def _sync_subscription(db, event) -> None:
    obj = event.data.object
    sub_id = obj.get("subscription") or obj.get("id")
    if not sub_id:
        return
    sub = stripe.Subscription.retrieve(sub_id)
    if sub.status not in ("active", "trialing"):
        return
    tenant_id = int(sub.metadata.get("tenant_id")
                    or obj.get("metadata", {}).get("tenant_id"))
    item = sub["items"]["data"][0]
    plan = ("business"
            if item["price"].id == PLANS["business"]["price_id"]
            else "team")
    db.execute("""
        UPDATE tenants SET plan = ?, seat_count = ?,
               stripe_subscription_id = ?,
               scan_limit_month = ?, llm_budget_month = ?
        WHERE id = ?
    """, (plan, item["quantity"], sub_id,
          PLANS[plan]["scan_limit"], PLANS[plan]["llm_budget"], tenant_id))


def _downgrade_to_free(db, event) -> None:
    sub = event.data.object
    tenant_id = int(sub.metadata.get("tenant_id") or 0)
    if tenant_id:
        db.execute("""
            UPDATE tenants SET plan = 'free',
                   scan_limit_month = ?, llm_budget_month = 0,
                   stripe_subscription_id = NULL
            WHERE id = ?
        """, (PLANS["free"]["scan_limit"], tenant_id))


# ── FastAPI billing routes ────────────────────────────────

from fastapi import APIRouter, HTTPException, Request

from gsc_cloud import billing
from gsc_cloud.store import control_plane

billing_router = APIRouter()
DASH_URL = os.environ.get("GSC_DASHBOARD_URL", "http://localhost:3000")


@billing_router.post("/api/v2/billing/checkout")
def checkout(request: Request, body: dict):
    from gsc_cloud.dash_api import _ctx
    uid, tid = _ctx(request)
    db = control_plane()
    row = db.fetchone(
        "SELECT role FROM memberships WHERE user_id = ? AND tenant_id = ?",
        (uid, tid))
    # GSC-05: enforce billing role — only owner/security may create checkout
    role = row["role"] if row else None
    if role not in ("owner", "security"):
        raise HTTPException(403, "insufficient role for billing checkout")
    url = billing.create_checkout(
        control_plane(tid), tid, body["plan"], int(body.get("seats", 1)),
        success_url=f"{DASH_URL}/billing?ok=1",
        cancel_url=f"{DASH_URL}/billing?cancel=1")
    return {"url": url}