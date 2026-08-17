# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_detectors → gsc_core.gsc_detectors (трек 0.5 packages split).

Пакетный shim: алиасирует пакет и ВСЕ его подмодули в namespace gsc_detectors,
чтобы внешние потребители (``from gsc_detectors.registry import ...``,
``from gsc_detectors import AuditContext``) работали без изменений.
"""
import sys as _sys
import importlib as _importlib
import pkgutil as _pkgutil

import gsc_core.gsc_detectors as _core

_sys.modules["gsc_detectors"] = _core

_prefix = _core.__name__ + "."
for _m in _pkgutil.walk_packages(_core.__path__, prefix=_prefix):
    _alias = "gsc_detectors" + _m.name[len(_core.__name__):]
    try:
        _sys.modules[_alias] = _importlib.import_module(_m.name)
    except Exception:
        pass
