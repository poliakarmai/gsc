# SPDX-License-Identifier: Apache-2.0
"""Shim: gsc_db_backend → gsc_cloud.gsc_db_backend (трек 0.5.3 packages split)."""
import sys as _sys
from gsc_cloud import gsc_db_backend as _impl
_sys.modules[__name__] = _impl
