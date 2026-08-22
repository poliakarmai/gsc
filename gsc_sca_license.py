# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_sca_license → gsc_core.gsc_sca_license (трек 0.5 packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_core.gsc_sca_license', run_name='__main__')

from gsc_core import gsc_sca_license as _impl
_sys.modules[__name__] = _impl
