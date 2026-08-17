# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Shim: gsc_mutation_tracker → gsc_cli.gsc_mutation_tracker (трек 0.5 packages split)."""
import sys as _sys
from gsc_cli import gsc_mutation_tracker as _impl

_sys.modules[__name__] = _impl
