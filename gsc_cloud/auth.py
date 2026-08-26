# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""API keys per tenant. Ключ хранится только как sha256-хэш.

Canonical multi-tenant auth helpers for the SaaS layer. Used by
``server.py`` (live MVP), ``apideps.tenant_ctx`` (FastAPI dependency)
and the legacy ``gsc_cloud/api_v2.py`` handlers. All raw keys carry
the ``gsk_`` prefix (GSC-010).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional, Tuple


class Unauthorized(Exception):
    pass


def generate_api_key() -> tuple[str, str]:
    """Return ``(raw_key, key_hash)``. The raw key is shown ONCE.

    GSC-010: unified ``gsk_`` prefix — matches ``server.py`` key minting.
    """
    raw = "gsk_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def auth_tenant(header_key: str, db) -> int:
    """Resolve ``header_key`` → ``tenant_id``. Constant-time hash compare.

    Raises :class:`Unauthorized` when the key is missing, has the wrong
    prefix, or no active row matches. Use this in FastAPI request paths
    that must fail-closed (see ``gsc_cloud.apideps.tenant_ctx``).
    """
    if not header_key or not header_key.startswith("gsk_"):
        raise Unauthorized()
    prefix = header_key[:12]
    expected_hash = hashlib.sha256(header_key.encode()).hexdigest()
    # Prefix index narrows the scan; ``compare_digest`` guards timing.
    rows = db.query(
        "SELECT tenant_id, key_hash FROM api_keys "
        "WHERE prefix = ? AND revoked_at IS NULL", (prefix,))
    for row in rows:
        if hmac.compare_digest(row["key_hash"], expected_hash):
            return row["tenant_id"]
    raise Unauthorized()


def verify_api_key(raw_key: str, db) -> Optional[int]:
    """Return ``tenant_id`` for ``raw_key`` or ``None`` if invalid/revoked.

    Canonical lookup: prefix-based SELECT over ``api_keys`` (active only),
    then ``hmac.compare_digest`` against the stored sha256 hash. Replaces
    the legacy ``gsc_cloud.tenancy.verify_api_key`` (which was a plain
    hash scan with no prefix filter) and the duplicate helper that used
    to live in ``gsc_cloud.server``.

    Use this for non-FastAPI callers (background workers, CLI tools,
    legacy ``/api/v2`` handlers) that prefer ``None``-on-failure over the
    raising :func:`auth_tenant` contract.
    """
    if not raw_key or not raw_key.startswith("gsk_"):
        return None
    prefix = raw_key[:8] if len(raw_key) >= 8 else raw_key
    expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    rows = db.query(
        "SELECT tenant_id, key_hash FROM api_keys "
        "WHERE key_prefix = ? AND revoked_at IS NULL",
        (prefix,),
    )
    for row in rows:
        if hmac.compare_digest(row["key_hash"], expected_hash):
            return row["tenant_id"]
    return None


def scoped_query(sql: str, tenant_id: int) -> Tuple[str, tuple]:
    """Inject a ``tenant_id`` predicate into ``sql``.

    Adds ``WHERE tenant_id = ?`` when the statement has no ``WHERE``
    clause yet, otherwise appends ``AND tenant_id = ?``. Returns
    ``(rewritten_sql, params_tuple)`` ready to pass to ``db.query``.

    Ported from the legacy ``gsc_cloud.tenancy.scoped_query``; kept as
    the canonical tenant-scoping helper so SQL stays single-source.
    """
    if "WHERE" in sql.upper():
        return sql + " AND tenant_id = ?", (tenant_id,)
    return sql + " WHERE tenant_id = ?", (tenant_id,)