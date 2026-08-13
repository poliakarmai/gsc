# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Cloud (S1): multi-tenant обвязка вокруг ядра сканера.

Граница S1: tenants, api_keys, repos, scans, findings, verdicts, usage.
Chains/mutations/overrides/invariants портируются в S2.
Внутренний контур (API v1, SQLite) не затрагивается.
"""