# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Сессии дашборда: подписанные httpOnly cookie.

Не JWT в localStorage: httpOnly недоступен XSS, SameSite=Lax
закрывает большинство CSRF-сценариев для top-level навигации.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

SESSION_TTL = 7 * 86400


def _secret() -> bytes:
    return os.environ["GSC_SESSION_SECRET"].encode()


def issue(user_id: int, tenant_id: int | None) -> str:
    payload = {"uid": user_id, "tid": tenant_id,
               "exp": int(time.time()) + SESSION_TTL}
    body = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}|{sig}"


def parse(cookie_value: str) -> dict | None:
    try:
        body, sig = cookie_value.rsplit("|", 1)
    except ValueError:
        return None
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    payload = json.loads(body)
    if payload.get("exp", 0) < time.time():
        return None
    return payload


COOKIE_OPTS = dict(httponly=True, secure=True, samesite="lax",
                   max_age=SESSION_TTL, path="/")