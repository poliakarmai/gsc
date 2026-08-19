# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_business_risk → gsc_core.gsc_business_risk (packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_core.gsc_business_risk', run_name='__main__')

from gsc_core import gsc_business_risk as _impl
_sys.modules[__name__] = _impl
