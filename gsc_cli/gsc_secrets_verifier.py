#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""GSC Secrets Verifier v1.1 — live-проверка секретов одним безопасным запросом.

Фаза 8. Live-проверка секретов: один запрос к API провайдера → 200 = live (TP),
401 = dead (FP). Убивает шум тестовых/мёртвых/placeholder-секретов.

Redaction: значение секрета НЕ логируется и НЕ сохраняется — только fingerprint.
Кэш: только `dead` (стабильный негатив), bounded. `live`/`unknown`/`error` не кэшируем
(транзиентные — не должны залипать).

Безопасность (verdict судьи 22.08): bypass proxy (bearer не должен утекать через
корпоративный TLS-инспектирующий прокси) + disable redirects (Authorization не
форвардится по редиректу) + нормализация значения до fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import time
from urllib.request import (Request, build_opener, ProxyHandler,
                            HTTPRedirectHandler)
from urllib.error import HTTPError, URLError

TIMEOUT = 10
DEAD_DEBOOST = 0.3
_CACHE_MAX = 1000
_CACHE: dict[str, dict] = {}

# Rate limiting + request budget (verdict судьи): не спамить провайдерские API.
_RATE_MIN_INTERVAL = 0.1   # мин. пауза между запросами
_REQUEST_BUDGET = 200      # максимум запросов за один run
_RATE_LOCK = threading.Lock()
_LAST_REQUEST = 0.0
_requests_this_run = 0


def is_test_key(secret: str) -> bool:
    """Тестовые/временные ключи: sk_test_/rk_test_ (Stripe test) и ASIA (AWS session token)."""
    s = (secret or "").strip().strip("'\"")
    return s.startswith(("sk_test_", "rk_test_", "ASIA"))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # не редиректить → Authorization не утекает на чужой хост


_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def detect_provider(secret: str) -> str:
    s = (secret or "").strip().strip("'\"")
    # только токены, которые реально проверимы одним запросом; ghs_/ghr_/xoxa-/
    # xoxr-/xapp- → unknown (нужен другой endpoint, не user-token)
    if s.startswith(("ghp_", "github_pat_", "gho_")):
        return "github"
    if s.startswith(("xoxb-", "xoxp-")):
        return "slack"
    if s.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_")):
        return "stripe"
    if s.startswith(("AKIA", "ASIA")):
        return "aws"
    if re.match(r"^(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://", s, re.IGNORECASE):
        return "db"
    return "unknown"


def _throttle():
    global _LAST_REQUEST
    with _RATE_LOCK:
        now = time.time()
        wait = _RATE_MIN_INTERVAL - (now - _LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        _LAST_REQUEST = time.time()


def _http(method: str, url: str, headers: dict):
    global _requests_this_run
    if _requests_this_run >= _REQUEST_BUDGET:
        return None, None  # бюджет исчерпан → unknown (не блокируем скан)
    # SSRF guard (defense-in-depth): provider API URLs are fixed, but never resolve to
    # the machine's own network position. Bypass the DNS cost with a small host cache.
    from gsc_core.gsc_ssrf_guard import guard_url
    try:
        guard_url(url)
    except PermissionError:
        return None, None  # blocked → unknown (не роняем скан, не делаем запрос)
    _throttle()
    _requests_this_run += 1
    req = Request(url, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode(errors="replace")[:2000]
    except HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:2000]
    except (URLError, ssl.SSLError, TimeoutError, OSError):
        return None, None


def verify_github(token: str) -> str:
    # fine-grained PAT / OAuth → Bearer; classic PAT → token (иначе false 401)
    scheme = "Bearer" if token.startswith(("github_pat_", "gho_")) else "token"
    st, _ = _http("GET", "https://api.github.com/user",
                  {"Authorization": f"{scheme} {token}",
                   "Accept": "application/vnd.github+json",
                   "User-Agent": "gsc-secrets-verifier"})
    if st == 200:
        return "live"
    if st == 401:
        return "dead"
    return "unknown"  # 403 = rate-limit / SAML-SSO → не доказывает dead


def verify_stripe(key: str) -> str:
    st, _ = _http("GET", "https://api.stripe.com/v1/account",
                  {"Authorization": f"Bearer {key}"})
    if st == 200:
        return "live"
    if st == 401:
        return "dead"
    return "unknown"  # 403 = restricted key → не доказывает dead


_SLACK_DEAD = ("invalid_auth", "token_revoked", "token_expired", "not_authed")


def verify_slack(token: str) -> str:
    st, body = _http("POST", "https://slack.com/api/auth.test",
                     {"Authorization": f"Bearer {token}",
                      "Content-Type": "application/json"})
    if st == 200 and body and '"ok":true' in body:
        return "live"
    if st == 401:
        return "dead"
    # whitelist dead-only ошибок; missing_scope/ratelimited/account_inactive —
    # токен жив, проба неуместна → unknown (иначе false dead)
    if st == 200 and body and any(e in body for e in _SLACK_DEAD):
        return "dead"
    return "unknown"


PROVIDER_VERIFIERS = {
    "github": verify_github,
    "stripe": verify_stripe,
    "slack": verify_slack,
}


def _normalize(value: str) -> str:
    return (value or "").strip().strip("'\"").strip()


def _fingerprint(provider: str, value: str) -> str:
    # нормализуем ДО хэша — quoted/unquoted формы дают один fingerprint
    return hashlib.sha256(f"{provider}:{_normalize(value)}".encode()).hexdigest()[:32]


def verify_secret(secret: str, provider: str = None) -> dict:
    """Проверить секрет. Возвращает {provider, status, fingerprint, cached}.

    status ∈ {live, dead, unknown, error}. Значение не сохраняется/логируется.
    """
    provider = provider or detect_provider(secret)
    fp = _fingerprint(provider, secret)
    if fp in _CACHE:
        return {**_CACHE[fp], "cached": True}
    fn = PROVIDER_VERIFIERS.get(provider)
    if fn is None:
        result = {"provider": provider, "status": "unknown",
                  "reason": "no verifier", "fingerprint": fp}
    else:
        try:
            status = fn(_normalize(secret))
        except Exception:
            status = "error"
        result = {"provider": provider, "status": status, "fingerprint": fp}
    # кэшируем только стабильный dead; live/unknown/error — транзиентные
    if result["status"] == "dead" and len(_CACHE) < _CACHE_MAX:
        _CACHE[fp] = result
    return result


def deboost_dead(findings: list, verify_fn=verify_secret) -> int:
    """Пометить dead-секреты (deboost confidence + severity→INFO).

    finding несёт значение в `value`/`secret_value` (этап детекта, в памяти).
    Возвращает число deboosted.
    """
    deboosted = 0
    for f in findings:
        value = f.get("value") or f.get("secret_value")
        if not value:
            continue
        r = verify_fn(value)
        if r["status"] == "dead":
            f["metadata"] = {**f.get("metadata", {}),
                             "secret_status": "dead", "secret_provider": r["provider"]}
            f["confidence"] = round(f.get("confidence", 0.8) * DEAD_DEBOOST, 2)
            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                f["severity"] = "INFO"
            deboosted += 1
    return deboosted


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: gsc_secrets_verifier.py <secret> [--provider github|slack|stripe]")
        sys.exit(1)
    secret = sys.argv[1]
    provider = None
    if "--provider" in sys.argv:
        provider = sys.argv[sys.argv.index("--provider") + 1]
    result = verify_secret(secret, provider)
    print(json.dumps({k: v for k, v in result.items() if k != "fingerprint"},
                     indent=2, ensure_ascii=False))
