# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GitHub OAuth для дашборда (S3).

Почему GitHub OAuth, а не email/пароль:
  - все клиенты приходят через GitHub App (нулевой дополнительный барьер);
  - login-идентичность уже доказана GitHub'ом;
  - членство в тенанте привязывается к github_id.
"""
from __future__ import annotations

import os
import secrets
import time

import requests
from urllib.parse import quote

GH_API = "https://api.github.com"
OAUTH_STATE_TTL = 600

# S-08: invite-only onboarding. When enabled (default), dashboard login
# requires a pending invite (by email or github_login) OR ownership via a
# GitHub App installation — an open signup is rejected with 403.
INVITE_ONLY = os.environ.get("GSC_INVITE_ONLY", "1").lower() in ("1", "true", "yes")


class OAuthError(Exception):
    pass


def begin_login(dedup_store) -> tuple[str, str]:
    """Возвращает (authorize_url, state). State хранится в Redis."""
    state = secrets.token_urlsafe(32)
    dedup_store.once_raw(f"gsc:oauth:{state}", OAUTH_STATE_TTL,
                         value="pending")
    params = {
        "client_id": os.environ["GSC_OAUTH_CLIENT_ID"],
        "redirect_uri": os.environ["GSC_OAUTH_REDIRECT_URI"],
        "scope": "read:user user:email",
        "state": state,
    }
    qs = "&".join(f"{k}={quote(str(v))}"
                  for k, v in params.items())
    return f"https://github.com/login/oauth/authorize?{qs}", state


def complete_login(code: str, state: str, dedup_store) -> dict:
    """Обмен code на токен, запрос профиля, upsert user."""
    if not dedup_store.consume(f"gsc:oauth:{state}"):
        raise OAuthError("invalid or expired state")
    resp = requests.post(
        "https://github.com/login/oauth/access_token",
        json={"client_id": os.environ["GSC_OAUTH_CLIENT_ID"],
              "client_secret": os.environ["GSC_OAUTH_CLIENT_SECRET"],
              "code": code},
        headers={"Accept": "application/json"}, timeout=10)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise OAuthError("token exchange failed")

    user = requests.get(f"{GH_API}/user",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10).json()
    return {"github_id": user["id"], "login": user["login"],
            "email": user.get("email"), "avatar_url": user.get("avatar_url")}


def upsert_user(db, gh_user: dict) -> int:
    db.execute("""
        INSERT INTO users (github_id, login, email, avatar_url,
                           last_login_at)
        VALUES (?, ?, ?, ?, now())
        ON CONFLICT (github_id) DO UPDATE SET
            login = excluded.login,
            email = COALESCE(excluded.email, users.email),
            avatar_url = excluded.avatar_url,
            last_login_at = now()
    """, (gh_user["github_id"], gh_user["login"], gh_user.get("email"),
          gh_user.get("avatar_url")))
    row = db.fetchone("SELECT id FROM users WHERE github_id = ?",
                      (gh_user["github_id"],))
    return row["id"]


def grant_owner_on_first_install(db, user_id: int, github_login: str):
    """Автор инсталляции, создавшей тенант (S2), становится owner'ом."""
    db.execute("""
        INSERT INTO memberships (user_id, tenant_id, role)
        SELECT ?, gi.tenant_id, 'owner'
        FROM github_installs gi
        WHERE gi.org_login = ?
        ON CONFLICT (user_id, tenant_id) DO NOTHING
    """, (user_id, github_login))


# ── FastAPI auth routes ───────────────────────────────────

from fastapi import APIRouter, HTTPException, Response
from gsc_cloud.dedup import DeliveryDedup
from gsc_cloud import session
from gsc_cloud.store import control_plane

auth_router = APIRouter()
dedup_store = DeliveryDedup()


@auth_router.post("/api/v2/auth/github/begin")
def auth_begin():
    url, _ = begin_login(dedup_store)
    return {"url": url}


@auth_router.post("/api/v2/auth/github/callback")
def auth_callback(code: str, state: str, response: Response):
    try:
        gh_user = complete_login(code, state, dedup_store)
    except OAuthError as e:
        raise HTTPException(401, str(e))
    db = control_plane()
    user_id = upsert_user(db, gh_user)

    if INVITE_ONLY:
        # Strict match: github_login is the identity — highest priority.
        # Email is only a fallback when the invite has no login bound.
        inv = db.fetchone(
            "SELECT id, tenant_id, role FROM invites "
            "WHERE status='pending' AND github_login = ? LIMIT 1",
            (gh_user["login"],))
        if not inv and gh_user.get("email"):
            inv = db.fetchone(
                "SELECT id, tenant_id, role FROM invites "
                "WHERE status='pending' AND github_login IS NULL "
                "AND email = ? LIMIT 1",
                (gh_user["email"],))
        if inv:
            # Atomic accept — guards against double-spend races.
            db.execute(
                "UPDATE invites SET status='accepted', accepted_at=now() "
                "WHERE id=? AND status='pending'", (inv["id"],))
            db.execute(
                "INSERT INTO memberships (user_id, tenant_id, role) "
                "VALUES (?, ?, ?) ON CONFLICT (user_id, tenant_id) DO NOTHING",
                (user_id, inv["tenant_id"], inv["role"]))
        else:
            # Legitimate fallback: ownership via GitHub App installation.
            grant_owner_on_first_install(db, user_id, gh_user["login"])
        db.commit()
        # Hard gate — open signup is rejected.
        m = db.fetchone("SELECT 1 FROM memberships WHERE user_id = ?", (user_id,))
        if not m:
            raise HTTPException(
                403, "This instance is invite-only. Ask an admin to invite you.")
    else:
        grant_owner_on_first_install(db, user_id, gh_user["login"])
        db.commit()

    tenant = db.fetchone("""
        SELECT tenant_id FROM memberships WHERE user_id = ?
        ORDER BY (role != 'owner'), created_at LIMIT 1
    """, (user_id,))
    tid = tenant["tenant_id"] if tenant else None
    # SSO-required тенант: GitHub OAuth заблокирован
    if tid:
        t = db.fetchone("SELECT sso_required FROM tenants WHERE id = ?",
                        (tid,))
        if t and t.get("sso_required"):
            raise HTTPException(403, "this tenant requires SSO login")
    cookie = session.issue(user_id, tid)
    response.set_cookie("gsc_session", cookie, **session.COOKIE_OPTS)
    return {"ok": True, "tenant_id": tid}