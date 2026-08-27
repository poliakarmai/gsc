# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GitHub App authentication (S2).

App JWT (уровень приложения, ≤10 мин) → installation access token
(уровень установки, TTL 1 час, кэш с запасом обновления).
"""
from __future__ import annotations

import os
import time
from datetime import datetime

import jwt as pyjwt
import requests

GH_API = "https://api.github.com"

_token_cache: dict[int, tuple[str, float]] = {}
REFRESH_MARGIN_SEC = 120        # обновляем за 2 минуты до истечения


def _app_id() -> str:
    return os.environ["GSC_APP_ID"]


def _private_key() -> str:
    return os.environ["GSC_APP_PRIVATE_KEY"]    # PEM, только env


def make_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,          # запас на расхождение часов GitHub
        "exp": now + 540,         # 9 минут (лимит GitHub: 10)
        "iss": _app_id(),
    }
    return pyjwt.encode(payload, _private_key(), algorithm="RS256")


def get_installation_token(installation_id: int) -> str:
    cached = _token_cache.get(installation_id)
    if cached and cached[1] > time.time() + REFRESH_MARGIN_SEC:
        return cached[0]
    resp = requests.post(
        f"{GH_API}/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": f"Bearer {make_jwt()}",
                 "Accept": "application/vnd.github+json"},
        timeout=10)
    resp.raise_for_status()
    data = resp.json()
    exp_ts = datetime.fromisoformat(
        data["expires_at"].replace("Z", "+00:00")).timestamp()
    _token_cache[installation_id] = (data["token"], exp_ts)
    return data["token"]


def gh_headers(installation_id: int) -> dict:
    return {"Authorization": f"Bearer {get_installation_token(installation_id)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}