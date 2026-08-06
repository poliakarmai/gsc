# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""FastAPI-зависимости: резолв тенанта из x-api-key."""
from __future__ import annotations

from fastapi import Header, HTTPException

from cloud.auth import Unauthorized, auth_tenant
from cloud.store import control_plane


def tenant_ctx(x_api_key: str = Header(default="")) -> int:
    try:
        db = control_plane()          # служебное соединение, без RLS
        return auth_tenant(x_api_key, db)
    except Unauthorized:
        raise HTTPException(status_code=401, detail="invalid api key")