# SPDX-License-Identifier: Apache-2.0
"""Shim: gsc_router → gsc_cloud.gsc_router (трек 0.5.3 packages split)."""
import sys as _sys
from gsc_cloud import gsc_router as _impl
_sys.modules[__name__] = _impl
