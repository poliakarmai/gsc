# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""API keys per tenant. Ключ хранится только как sha256-хэш."""
from __future__ import annotations

import hashlib
import hmac
import secrets


class Unauthorized(Exception):
    pass


def generate_api_key() -> tuple[str, str]:
    """Возвращает (raw_key, key_hash). raw показывается ОДИН раз."""
    raw = "gsc_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def auth_tenant(header_key: str, db) -> int:
    """header_key → tenant_id. Constant-time сравнение хэшей."""
    if not header_key or not header_key.startswith("gsc_"):
        raise Unauthorized()
    prefix = header_key[:12]
    expected_hash = hashlib.sha256(header_key.encode()).hexdigest()
    # Ищем по префиксу, сравниваем хэш через compare_digest
    rows = db.query(
        "SELECT tenant_id, key_hash FROM api_keys "
        "WHERE prefix = ? AND revoked_at IS NULL", (prefix,))
    for row in rows:
        if hmac.compare_digest(row["key_hash"], expected_hash):
            return row["tenant_id"]
    raise Unauthorized()