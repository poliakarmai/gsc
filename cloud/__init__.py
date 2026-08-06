"""GSC Cloud (S1): multi-tenant обвязка вокруг ядра сканера.

Граница S1: tenants, api_keys, repos, scans, findings, verdicts, usage.
Chains/mutations/overrides/invariants портируются в S2.
Внутренний контур (API v1, SQLite) не затрагивается.
"""