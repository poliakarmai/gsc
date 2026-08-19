# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""MCP auth + repo-path scoping.

ADR-0001 триггер активирован (HTTP/SSE transport / multi-tenant): MCP выводится
на сетевой транспорт — добавляем два рубежа:

1. **Auth (кто имеет доступ).** `GSCMCPAuth` — FastMCP `TokenVerifier`,
   валидирует `Authorization: Bearer <token>` на transport-уровне.
   Разрешение токена в два режима:
     - on-prem / single-tenant: статический ``GSC_MCP_TOKEN`` (+ ``GSC_MCP_TENANT``);
     - cloud / multi-tenant: ``gsk_``-ключ через ``gsc_cloud.auth.auth_tenant`` (PG).

2. **Path scoping (что можно сканировать).** ``resolve_repo_path`` раскрывает
   symlinks/``..`` через ``realpath`` и запрещает выход за ``GSC_ALLOWED_ROOTS``
   (список разрешённых корней через запятую). Применяется к ``scan_repo`` и
   ``verify_finding``.

Fail-closed: при HTTP/SSE транспорте без сконфигурированного auth ``verify_token``
возвращает ``None`` → все запросы отклоняются. stdio-транспорт auth не
консультирует (локальный доверенный процесс — ADR-0001, решение 1).
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
    """Разрешённые корни из ``GSC_ALLOWED_ROOTS`` (через запятую).

    Каждый элемент нормализуется через ``realpath`` (раскрытие ``~``, symlinks,
    ``..``). Пустая переменная → ограничений нет (локальный stdio-режим).
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
    """Разрешить и проверить путь репозитория.

    Возвращает ``(resolved_abs_path, error_or_None)``. Порядок проверок:
      1. пустой путь → ошибка;
      2. ``realpath`` (symlink + ``..``) должен лежать внутри ``GSC_ALLOWED_ROOTS``
         (если ограничение задано);
      3. путь должен существовать и быть директорией.
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
    """True, если задан хотя бы один источник auth (иначе HTTP fail-closed)."""
    return bool(os.environ.get("GSC_MCP_TOKEN", "").strip()) or bool(
        os.environ.get("GSC_DATABASE_URL", "").strip()
    )


def resolve_token(token: str) -> int | None:
    """Bearer-токен → tenant_id. ``None`` = невалиден или auth не настроен.

    Приоритет:
      1. ``GSC_MCP_TOKEN`` (on-prem, constant-time compare);
      2. ``GSC_DATABASE_URL`` + ``gsk_``-ключ (cloud, через ``auth_tenant``).
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
    """Bearer-token верификатор для FastMCP (HTTP/SSE transport).

    ``verify_token`` возвращает ``AccessToken`` с ``claims={"tenant_id": tid}`` —
    этот tenant_id доступен в тулах через ``get_access_token()`` и используется
    для аудита/скоупинга.
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
