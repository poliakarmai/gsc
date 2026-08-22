#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""GSC Secrets Verifier v1.0 — live-проверка секретов одним безопасным запросом.

Фаза 8. TruffleHog-идея: один запрос к API провайдера → 200 = live (TP),
401/403 = dead (FP). Убивает шум тестовых/мёртвых/placeholder-секретов —
основной источник низкой precision CRITICAL (~8–12%).

Redaction: значение секрета НЕ логируется и НЕ сохраняется — только fingerprint.
Кэш: sha256(provider:value) → status, чтобы не дёргать API повторно на ре-скане.

Провайдеры: GitHub / Slack / Stripe (один запрос, без подписи). AWS/DB — TODO
(требуют SigV4 / network-connect к хосту).
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

TIMEOUT = 10
_CACHE: dict[str, dict] = {}


def detect_provider(secret: str) -> str:
    s = (secret or "").strip().strip("'\"")
    if s.startswith(("ghp_", "github_pat_", "gho_", "ghs_", "ghr_")):
        return "github"
    if s.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxr-")):
        return "slack"
    if s.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_")):
        return "stripe"
    if s.startswith(("AKIA", "ASIA")):
        return "aws"
    if re.match(r"^(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://", s, re.IGNORECASE):
        return "db"
    return "unknown"


def _http(method: str, url: str, headers: dict):
    req = Request(url, method=method, headers=headers)
    try:
        with urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode(errors="replace")[:2000]
    except HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:2000]
    except (URLError, ssl.SSLError, TimeoutError, OSError):
        return None, None


def verify_github(token: str) -> str:
    st, _ = _http("GET", "https://api.github.com/user",
                  {"Authorization": f"token {token}",
                   "Accept": "application/vnd.github+json"})
    if st == 200:
        return "live"
    if st in (401, 403):
        return "dead"
    return "unknown"


def verify_stripe(key: str) -> str:
    st, _ = _http("GET", "https://api.stripe.com/v1/account",
                  {"Authorization": f"Bearer {key}"})
    if st == 200:
        return "live"
    if st == 401:
        return "dead"
    return "unknown"  # 403 = restricted key → не доказывает dead


def verify_slack(token: str) -> str:
    st, body = _http("POST", "https://slack.com/api/auth.test",
                     {"Authorization": f"Bearer {token}",
                      "Content-Type": "application/json"})
    if st == 200 and body and '"ok":true' in body:
        return "live"
    if st == 401:
        return "dead"
    if st == 200 and body and ('"ok":false' in body or "invalid_auth" in body):
        return "dead"
    return "unknown"


PROVIDER_VERIFIERS = {
    "github": verify_github,
    "stripe": verify_stripe,
    "slack": verify_slack,
}


def _fingerprint(provider: str, value: str) -> str:
    return hashlib.sha256(f"{provider}:{value}".encode()).hexdigest()[:32]


def verify_secret(secret: str, provider: str = None) -> dict:
    """Проверить секрет. Возвращает {provider, status, fingerprint, cached}.

    status ∈ {live, dead, unknown, error}. Значение секрета не сохраняется и не
    логируется — только fingerprint.
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
            status = fn(secret.strip().strip("'\""))
        except Exception:
            status = "error"
        result = {"provider": provider, "status": status, "fingerprint": fp}
    _CACHE[fp] = result
    return result


def deboost_dead(findings: list, verify_fn=verify_secret) -> int:
    """Пометить dead-секреты как FP (deboost confidence) — TruffleHog-стиль.

    finding должен нести значение секрета в поле `value`/`secret_value` (этап
    детекта, в памяти — значение не персистится). Возвращает число deboosted.
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
            f["confidence"] = round(f.get("confidence", 0.8) * 0.3, 2)
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
    # никогда не выводить значение — только статус и fingerprint
    result.pop("fingerprint", None) if result.get("status") == "unknown" else None
    print(json.dumps({k: v for k, v in result.items() if k != "fingerprint"},
                     indent=2, ensure_ascii=False))
