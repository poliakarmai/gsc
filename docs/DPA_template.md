# Data Processing Agreement (DPA) — GSC Cloud

## 1. Parties

**Controller:** Customer (tenant)
**Processor:** GSC Cloud (Поляков Алексей)

## 2. Purpose of Processing

Security scanning of source code repositories for vulnerabilities.
Data is processed exclusively to deliver the GSC service.

## 3. Categories of Data

| Category | Stored | Retention |
|---|---|---|
| Source code | NO (ephemeral workers) | Deleted after scan |
| Findings / snippets | YES | Tenant lifetime |
| Audit events | YES | 7 years (SOC 2) |
| Billing events | YES | 7 years (tax compliance) |
| User profiles (login, email) | YES | Tenant lifetime |
| API keys | YES (hashed only) | Tenant lifetime |
| Scan artifacts (reports) | YES (object storage) | 90 days |

## 4. Sub-processors

| Sub-processor | Purpose | Location |
|---|---|---|
| DeepSeek | LLM revalidation of findings | API, no data stored |
| Hosting provider | Infrastructure | Hetzner / EU |
| Stripe | Payment processing | Stripe infrastructure |
| GitHub | OAuth identity / Marketplace | GitHub infrastructure |

## 5. Data Subject Rights

- **Access:** All data visible in dashboard
- **Rectification:** Verdicts (tp/fp/fixed), overrides
- **Deletion:** 30-day grace flow (`/api/v2/tenant/delete`)
- **Portability:** JSON/CSV export of findings, chains, audit log

## 6. Security Measures

- PostgreSQL Row-Level Security (RLS) with FORCE RLS
- API keys: SHA-256 hashed at rest
- Audit log: append-only with hash chain (tamper-evident)
- Session cookies: httpOnly, Secure, SameSite=Lax, HMAC-signed
- Webhook verification: HMAC-SHA256 signature on raw body
- Code: ephemeral workers (cloned, scanned, deleted per job)

## 7. Incident Notification

72-hour notification to affected tenants via email (billing_email)
for any confirmed data breach.

## 8. Deletion on Termination

1. Tenant requests deletion (dashboard or API)
2. 30-day grace period (reversible by support)
3. Cascade deletion: all tenant-scoped data removed
4. Audit trail of deletion preserved in admin-only log
