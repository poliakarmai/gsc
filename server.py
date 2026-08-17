# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: server → gsc_cloud.server (трек 0.5.3 packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_cloud.server', run_name='__main__')

from gsc_cloud import server as _impl
_sys.modules[__name__] = _impl
