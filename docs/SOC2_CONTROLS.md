# SOC 2 Type I — Controls Map for GSC Cloud

> Автоматически генерируемый документ. Актуальная evidence-папка: `scripts/gsc_evidence_pack.py`

## Trust Services Criteria Coverage

| TSC | Control | Implementation |
|-----|---------|---------------|
| CC6.1 | Logical access | API keys (hashed), GitHub OAuth / SSO, role-based |
| CC6.2 | New users | JIT provisioning with domain check, default role=developer |
| CC6.3 | Data isolation | tenant_id + PostgreSQL RLS + FORCE RLS |
| CC6.6 | Secure transmission | TLS-only (secure=True cookies, https-only webhooks) |
| CC6.7 | Third-party data sharing | DPA, ephemeral workers (code not stored) |
| CC7.2 | Anomaly monitoring | Webhook signature failures, quota 402, audit log |
| CC7.4 | Incident response | Audit hash chain as forensics, runbook |
| CC8.1 | Change management | CI gates: full test suite + calibration + apply-plan with rollback |
| A1.2 | Availability | Health checks, retry queue, PG backup with restore drill |
| P3.2 | Data deletion | Deletion flow with 30-day grace + cascade verification |

## Evidence

- `audit_chain_verify.json` — hash chain integrity for all tenants
- `calibration_report.txt` — 13/13 calibration projects
- `tests_report.txt` — full test suite results
- `access_review.json` — all memberships and roles
- RLS probe: cross-tenant read attempt → 0 rows (executable isolation proof)

## DPA Template

See `docs/DPA_template.md` for the full Data Processing Agreement.