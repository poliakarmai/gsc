# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Core package — движок, не зависящий от CLI/cloud.

Трек 0.5 (packages split): сюда переносятся движковые модули
(gsc_db, gsc_blocking, gsc_detectors, gsc_invariant_engine, gsc_ast_dataflow,
gsc_compliance, gsc_sca, gsc_epss, gsc_federated). Корневые shim-модули
сохраняют обратную совместимость через module-aliasing.
"""
