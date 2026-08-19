# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_correlation → gsc_core.gsc_correlation (трек 0.5 packages split).

Module-aliasing: любой ``import gsc_correlation`` / ``from gsc_correlation import X``
резолвится в gsc_core.gsc_correlation без повторной загрузки и без цикла.
"""
import sys as _sys
from gsc_core import gsc_correlation as _impl

_sys.modules[__name__] = _impl
