# SPDX-License-Identifier: Apache-2.0
"""Shim: gsc_scan_worker → gsc_cloud.gsc_scan_worker (трек 0.5.3 packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_cloud.gsc_scan_worker', run_name='__main__')

from gsc_cloud import gsc_scan_worker as _impl
_sys.modules[__name__] = _impl
