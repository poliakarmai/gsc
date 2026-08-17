# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_ast_dataflow → gsc_core.gsc_ast_dataflow (трек 0.5 packages split).

Module-aliasing: любой ``import gsc_ast_dataflow`` / ``from gsc_ast_dataflow import X``
резолвится в gsc_core.gsc_ast_dataflow без повторной загрузки и без цикла.
"""
import sys as _sys
from gsc_core import gsc_ast_dataflow as _impl

_sys.modules[__name__] = _impl
