# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""OIDC SSO для Business+ тенантов.

Поддерживается любой OIDC-провайдер (Okta, Azure AD, Google Workspace):
  - конфигурация на тенант (issuer, client_id, allowed domains);
  - JIT provisioning: пользователь с подтверждённым email-доменом
    получает роль developer (НЕ owner);
  - state + nonce обязательны (урок OAuth S3).
"""
from __future__ import annotations

import os
import secrets
import time

import requests
import jwt
from jwt import InvalidTokenError, PyJWKClient
from authlib.integrations.requests_client import OAuth2Session

from gsc_cloud import audit
from gsc_cloud.session import COOKIE_OPTS, issue as issue_session

NONCE_TTL = 600
REDIRECT_URI = os.environ.get("GSC_SSO_REDIRECT_URI",
                               "http://localhost:3000/api/auth/sso/callback")


class SSOError(Exception):
    pass


def _oidc_discovery(issuer_url: str) -> dict:
    resp = requests.get(f"{issuer_url.rstrip('/')}/.well-known/"
                        "openid-configuration", timeout=10)
    resp.raise_for_status()
    return resp.json()


def begin_sso(db, tenant_id: int, dedup_store) -> str:
    t = db.fetchone("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
    if not t or not t["sso_issuer_url"]:
        raise SSOError("SSO not configured for tenant")
    disc = _oidc_discovery(t["sso_issuer_url"])
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    dedup_store.once_raw(f"gsc:sso:{state}", NONCE_TTL, value=nonce)
    session = OAuth2Session(t["sso_client_id"],
                            scope="openid email profile",
                            redirect_uri=REDIRECT_URI)
    url, _ = session.create_authorization_url(
        disc["authorization_endpoint"], state=state, nonce=nonce)
    return url


def complete_sso(db, tenant_id: int, code: str, state: str,
                 dedup_store) -> tuple[int, str]:
    """Возвращает (user_id, session_cookie)."""
    stored = dedup_store.consume(f"gsc:sso:{state}")
    if not stored:
        raise SSOError("invalid or expired state")
    # stored value is the nonce (bytes in fakeredis, str in real)
    expected_nonce = stored.decode() if isinstance(stored, bytes) else stored

    t = db.fetchone("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
    disc = _oidc_discovery(t["sso_issuer_url"])
    session = OAuth2Session(t["sso_client_id"],
                            redirect_uri=REDIRECT_URI)
    token = session.fetch_token(disc["token_endpoint"], code=code)
    claims = _verify_id_token(disc, token["id_token"],
                              t["sso_client_id"], expected_nonce)

    email = (claims.get("email") or "").lower()
    domain = email.split("@", 1)[1] if "@" in email else ""
    sso_domains = t.get("sso_domains") or []
    if isinstance(sso_domains, str):
        import json; sso_domains = json.loads(sso_domains)
    if domain not in sso_domains:
        raise SSOError(f"email domain not allowed: {domain}")

    subject = claims["sub"]
    login = email.split("@")[0][:60]
    db.execute("""
        INSERT INTO users (login, email, sso_subject)
        VALUES (?, ?, ?)
        ON CONFLICT (sso_subject) DO UPDATE SET
            email = excluded.email, last_login_at = now()
    """, (login, email, subject))
    user_id = db.fetchone("SELECT id FROM users WHERE sso_subject = ?",
                          (subject,))["id"]
    db.execute("""
        INSERT INTO memberships (user_id, tenant_id, role)
        VALUES (?, ?, 'developer')
        ON CONFLICT (user_id, tenant_id) DO NOTHING
    """, (user_id, tenant_id))
    audit.record(db, tenant_id, email, "sso.login", "user",
                 str(user_id), {"subject": subject})
    db.commit()
    return user_id, issue_session(user_id, tenant_id)


def _verify_id_token(disc: dict, id_token: str, client_id: str,
                     expected_nonce: str) -> dict:
    jwks_client = PyJWKClient(disc["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    alg = signing_key.algorithm or "RS256"
    try:
        claims = jwt.decode(
            id_token, signing_key.key,
            algorithms=[alg],
            options={"verify_aud": False},  # aud проверяем ниже (может быть списком)
        )
    except InvalidTokenError as e:
        raise SSOError(f"id_token verification failed: {e}")
    aud = claims.get("aud")
    aud_ok = client_id in (aud if isinstance(aud, list) else [aud])
    if not aud_ok:
        raise SSOError("audience mismatch")
    if claims.get("iss") != disc["issuer"]:
        raise SSOError("issuer mismatch")
    if claims.get("nonce") != expected_nonce:
        raise SSOError("nonce mismatch")
    return claims