# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_db → gsc_core.gsc_db (трек 0.5 packages split).

Module-aliasing: любой ``import gsc_db`` / ``from gsc_db import X``
резолвится в gsc_core.gsc_db без повторной загрузки и без цикла.
"""
import sys as _sys
from gsc_core import gsc_db as _impl

_sys.modules[__name__] = _impl
