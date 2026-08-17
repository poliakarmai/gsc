# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_compliance → gsc_core.gsc_compliance (трек 0.5 packages split)."""
import sys as _sys
from gsc_core import gsc_compliance as _impl

_sys.modules[__name__] = _impl
