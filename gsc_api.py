# SPDX-License-Identifier: Apache-2.0
"""Shim: gsc_api → gsc_cloud.gsc_api (трек 0.5.3 packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_cloud.gsc_api', run_name='__main__')

from gsc_cloud import gsc_api as _impl
_sys.modules[__name__] = _impl
