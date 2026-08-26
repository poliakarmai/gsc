# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: cloud → gsc_cloud (трек 0.5.3 packages split).

Пакетный shim: алиасирует бывшие cloud-модули в namespace ``cloud``, чтобы
внешние потребители (``from cloud.api import app``, ``from cloud.store import
control_plane``, ``python -m cloud.workers`` через физический shim ниже)
работали без изменений. Деплой-артефакты (docker-compose, Dockerfile,
schema_*.sql, nginx, .env) остаются в этом каталоге.
"""
import sys as _sys
import importlib as _importlib
import pkgutil as _pkgutil

import gsc_cloud as _cloud

_sys.modules["cloud"] = _cloud

# Бывшие cloud-модули (без gsc_* инфра и server.py).
# DD-04: legacy ``tenancy`` removed — canonical helpers live in
# ``gsc_cloud.auth`` (verify_api_key, scoped_query).
_CLOUD_MODULES = {
    "agent_api", "apideps", "api", "api_v2", "audit", "auth", "billing",
    "canary", "dash_api", "data_lifecycle", "dedup", "federated_server",
    "github_auth", "github_oidc", "github_worker", "manage", "marketplace",
    "mutations_cloud", "observability", "onboarding", "pr_commands", "publish",
    "scanjobs", "scan_queue", "session", "sso", "store",
    "user_auth", "webhook", "worker", "workers",
}

_prefix = _cloud.__name__ + "."
for _m in _pkgutil.walk_packages(_cloud.__path__, prefix=_prefix):
    _local = _m.name[len(_prefix):]
    if _local in _CLOUD_MODULES:
        try:
            _sys.modules["cloud." + _local] = _importlib.import_module(_m.name)
        except Exception:
            pass
