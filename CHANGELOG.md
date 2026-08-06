# GSC Cloud 1.0 — Changelog

> Release: 2026-08-06 | Version: 1.0.0 | Tests: 98/98

## What is GSC Cloud?

Git Security Checker Cloud — multi-tenant SaaS scanner with LLM revalidation,
now with full billing, SSO, audit log, and marketplace distribution.

## Journey

| Version | Milestone |
|---|---|
| v0.11 | MVP: regex + LLM scanner |
| v0.21–v0.26 | Production rollout: CI, feedback, blocking engine |
| S1 (v0.27) | Multi-tenant: PG + RLS + queue + API keys |
| S2 (v0.28) | GitHub App: webhooks, deep subsystems in PG |
| S3 (v0.30) | Dashboard + Stripe: product layer |
| S4 (v1.0) | Trust & Growth: audit, SSO, DPA, marketplace |

## Features (Cloud 1.0)

- **25 detectors** (GS001–GS028) with LLM revalidation
- **Multi-tenant** with PostgreSQL RLS isolation
- **GitHub App** integration: PR gate, /gsc commands, verdicts
- **Web Dashboard** (Next.js): repos, findings, chains, mutations, usage
- **GitHub OAuth** + **SSO (OIDC)** for Business+
- **Stripe billing**: seat-based subscriptions, webhook, idempotent
- **GitHub Marketplace**: plan sync via signed webhook
- **Audit log** with hash chain (tamper-evident, SOC 2 ready)
- **DPA/GDPR**: 30-day grace deletion flow, data classification
- **Observability**: health, readiness, metrics

## Tech Stack

| Layer | Technology |
|---|---|
| Scanner core | Python, regex + DeepSeek LLM |
| Cloud backend | FastAPI + PostgreSQL 16 + Redis |
| Dashboard | Next.js 14 + TypeScript |
| Billing | Stripe |
| Auth | GitHub OAuth + OIDC SSO |
| Isolation | Row-Level Security (FORCE RLS) |

## GA Gate

| Criterion | Status |
|---|---|
| Tests (98/98 cloud + 8/8 core) | ✅ |
| Calibration (17/17) | ✅ |
| RLS multi-tenant isolation | ✅ |
| Stripe webhook idempotent | ✅ |
| Audit hash chain verified | ✅ |
| DPA + deletion flow | ✅ |
| SOC 2 controls map | ✅ |
| Evidence pack automatable | ✅ |

## What's Next (S5+)

- SOC 2 Type I audit (external auditor)
- GitHub Marketplace listing approval
- SSO provider-specific guides (Okta, Azure AD, Google)
- Overage purchases (v2 billing)
- SOC 2 Type II (observation period started)