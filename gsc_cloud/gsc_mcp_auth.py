# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""MCP auth + repo-path scoping.

ADR-0001 trigger activated (HTTP/SSE transport / multi-tenant): MCP is now
exposed over a network transport, so two boundaries are added:

1. **Auth (who has access).** ``GSCMCPAuth`` — a FastMCP ``TokenVerifier`` that
   validates ``Authorization: Bearer <token>`` at the transport layer. Token
   resolution runs in two modes:
     - on-prem / single-tenant: static ``GSC_MCP_TOKEN`` (+ ``GSC_MCP_TENANT``);
     - cloud / multi-tenant: ``gsk_`` key via ``gsc_cloud.auth.auth_tenant`` (PG).

2. **Path scoping (what may be scanned).** ``resolve_repo_path`` resolves
   symlinks/``..`` via ``realpath`` and rejects paths outside ``GSC_ALLOWED_ROOTS``
   (comma-separated allowlist of roots). Applied to ``scan_repo`` and
   ``verify_finding``.

Fail-closed: on HTTP/SSE transport without configured auth, ``verify_token``
returns ``None`` → every request is rejected. stdio transport does not consult
auth (local trusted process — ADR-0001, decision 1).
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastmcp.server.auth import TokenVerifier
from mcp.server.auth.provider import AccessToken


# ---------------------------------------------------------------------------
# Path scoping
# ---------------------------------------------------------------------------
def allowed_roots() -> list[Path]:
    """Allowed roots from ``GSC_ALLOWED_ROOTS`` (comma-separated).

    Each entry is normalized through ``realpath`` (expands ``~``, symlinks and
    ``..``). Empty variable → no restriction (local stdio mode).
    """
    raw = os.environ.get("GSC_ALLOWED_ROOTS", "").strip()
    if not raw:
        return []
    roots: list[Path] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            roots.append(Path(os.path.realpath(os.path.expanduser(part))))
    return roots


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_repo_path(repo_path: str) -> tuple[Path, str | None]:
    """Resolve and validate a repository path.

    Returns ``(resolved_abs_path, error_or_None)``. Checks, in order:
      1. empty path → error;
      2. ``realpath`` (symlink + ``..``) must stay within ``GSC_ALLOWED_ROOTS``
         (when the allowlist is set);
      3. the path must exist and be a directory.
    """
    if not repo_path or not str(repo_path).strip():
        return Path("."), "empty repo_path"

    real = Path(os.path.realpath(os.path.expanduser(str(repo_path))))
    roots = allowed_roots()
    if roots and not any(_is_within(real, r) for r in roots):
        return real, f"repo_path outside allowed roots: {real}"

    if not real.is_dir():
        return real, f"not a directory: {real}"

    return real, None


# ---------------------------------------------------------------------------
# Token resolution
# ---------------------------------------------------------------------------
def auth_configured() -> bool:
    """True if at least one auth source is set (otherwise HTTP is fail-closed)."""
    return bool(os.environ.get("GSC_MCP_TOKEN", "").strip()) or bool(
        os.environ.get("GSC_DATABASE_URL", "").strip()
    )


def resolve_token(token: str) -> int | None:
    """Bearer token → tenant_id. ``None`` = invalid or auth not configured.

    Priority:
      1. ``GSC_MCP_TOKEN`` (on-prem, constant-time compare);
      2. ``GSC_DATABASE_URL`` + ``gsk_`` key (cloud, via ``auth_tenant``).
    """
    if not token:
        return None

    # 1) on-prem static token (single-tenant)
    static = os.environ.get("GSC_MCP_TOKEN", "").strip()
    if static:
        if hmac.compare_digest(token, static):
            try:
                return int(os.environ.get("GSC_MCP_TENANT", "0"))
            except ValueError:
                return 0
        return None

    # 2) cloud per-tenant gsk_ key (PG control plane)
    if os.environ.get("GSC_DATABASE_URL", "").strip():
        try:
            from gsc_cloud.auth import Unauthorized, auth_tenant
            from gsc_cloud.store import control_plane

            db = control_plane()
            try:
                return auth_tenant(token, db)
            finally:
                db.close()
        except Unauthorized:
            return None
        except Exception:
            return None

    return None


class GSCMCPAuth(TokenVerifier):
    """Bearer-token verifier for FastMCP (HTTP/SSE transport).

    ``verify_token`` returns an ``AccessToken`` with ``claims={"tenant_id": tid}``
    — that tenant_id is available inside tools via ``get_access_token()`` and is
    used for audit/scoping.
    """

    def __init__(self, resolver=None):
        super().__init__()
        self._resolver = resolver or resolve_token

    async def verify_token(self, token: str) -> AccessToken | None:
        tid = self._resolver(token)
        if tid is None:
            return None
        return AccessToken(
            token=token,
            client_id="gsc-mcp",
            scopes=["scan"],
            subject=f"tenant:{tid}",
            claims={"tenant_id": tid},
        )
