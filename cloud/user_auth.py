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
from cloud.dedup import DeliveryDedup
from cloud import session
from cloud.store import control_plane

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