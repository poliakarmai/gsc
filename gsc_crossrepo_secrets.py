# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_crossrepo_secrets → gsc_cli.gsc_crossrepo_secrets (трек 0.5 packages split)."""
import sys as _sys

if __name__ == "__main__":
    import runpy
    runpy.run_module('gsc_cli.gsc_crossrepo_secrets', run_name='__main__')

from gsc_cli import gsc_crossrepo_secrets as _impl
_sys.modules[__name__] = _impl
