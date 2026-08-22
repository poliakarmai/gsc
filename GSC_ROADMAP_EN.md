# GSC Roadmap

> **v1.4.0** · 47 detectors (43 registry + 4 engines) · schema 33 · 165 modules · 610 tests
> **Priority #1: Precision** — drive FP down to a level ready for pilots (Phase 8).

---

## Phases

### Phase 1 — Packages split ✅
Physical split of the monolith into `gsc_core` / `gsc_cli` / `gsc_cloud` with shim compatibility.

- ✅ 0.5.1 engine + detectors → `gsc_core/`
- ✅ 0.5.2 CLI + scanners → `gsc_cli/`
- ✅ 0.5.3 SaaS → `gsc_cloud/`
- ✅ 0.5.4 collector + tests
- ✅ 0.5.5 shims + cleanup (272+ tests green)

### Phase 2 — Runtime Validator (IAST) 🟡
Proof-of-Fix verification based on actual runtime exploitation, not a stdout marker.

- ✅ Phase 1 — in-process monkeypatch (`open`/`subprocess`/`socket`) → JSONL
- ✅ Phase 2 — strace validation (`openat`/`connect`/`execve`)
- ⏳ Phase 3 — Falco/Tetragon agent (enterprise on-prem, >10 tenants) — deferred

### Phase 3 — Sale-Readiness 🟡
Readiness for buyer due-diligence.

- ✅ pytest collectible, evidence-backed README, MCP server (read-only)
- ⏳ design partners + paid pilots (business)
- ⏳ IP: waivers, chain-of-title (legal)
- ❌ benchmark vs Semgrep/CodeQL/Bandit
- ❌ enterprise hardening (sandbox threat model, egress, LLM retention)

### Phase 4 — GSC Bot 📝
GitHub App for viral verification of third-party PRs (`@gsc scan` → badge + check-run). Designed (`docs/GSC_BOT.md`), ~2 weeks.

### Phase 5 — JS/TS/Go language support 📝
Lift the growth ceiling (currently Python-first; 0–weak TPR on Java/JS/Go). Focus top-5 detectors, ~2–3 weeks.

### Phase 6 — Security Debt Ledger 📝
Translate technical risk into money: severity + EPSS → annualized loss. The language of budget for CISOs. ~1–2 weeks.

### Phase 7 — Agentic Self-Healing 📝
patch → test → retry until success (on top of the existing `gsc_selfhealing.py`). ~2 weeks.

### Phase 8 — Precision 🔄 (priority #1)
FP reduction. Goal: precision CRIT ≥50%, HIGH ≥40% before pilots start.

- ✅ GS008 (bare eval) + data-quality (395K rule_id) + CVE→inactive + bare chmod/Rust-unsafe deactivated
- ✅ 100-project re-measure (22.08): CRIT 4302 → **1309**, recall 10/10, precision CRIT ~15% (was ~4–5%)
- 🔄 next: GS001 (613 CRIT = 47%) — secrets extractor, main FP cluster (django 343, next.js 165, ruff 111)

### Phase 9 — Traction / GTM ⚠️
4★, 0 forks → 100+.

- ICP focus: mid-size SaaS with active CI/CD
- Niche: security for LLM-generated code (GS025 AI-provenance is the ace)
- Free/paid boundary documented explicitly

### Phase 10 — DD audit ✅
Supply-chain immutability + reproducible benchmark as the evidence base.

- ✅ 0.14.1 sandbox escape CI (Docker + fail-closed gate)
- ✅ 0.14.2 100-project benchmark (pinned revisions)
- ✅ 0.14.3 SBOM + provenance
- ✅ 0.14.4 digest-pinned images
- ✅ 0.14.5 AutoFix draft-only

### Phase 11 — Enterprise Security Hardening 🔜
Close the P0/P1 areas of the independent DD audit (2026-08-23) before the enterprise pilot.

- ✅ DD-01 authlib.jose → PyJWT (SSO), DD-02 claims 42→47, DD-04 .env.example (544c063)
- ⏳ Cloud API dynamic audit (auth bypass / injection / path traversal) — gsc_cloud/* + server.py
- ⏳ Tenant isolation: SQL schema tenant_id in PK/FK + RLS (PostgreSQL S1) — DD-05
- ⏳ Sandbox hardening: gsc_pof_sandbox.py setrlimit → container / network-disabled
- ⏳ CI hardening: upper bounds in deps + 0 skipped in CI

---

## Cross-cutting tracks

### Legal foundation 🟡
BSL → Apache 2.0 + Commercial ✅, SPDX ✅, CLA ✅, gitleaks ✅, license audit ✅, authorship evidence ✅. **Trademark ⏳** (1 week).

### SaaS Cloud (S1–S4) 📝
Designed (~16–20 weeks): S1 PostgreSQL+RLS → S2 GitHub App → S3 Dashboard+Stripe → S4 SOC2+Marketplace. Positioned as single-tenant/self-hosted until S1.

### Enterprise hybrid agent 📝
Runner + activation + air-gap. 2–3 weeks (after S1).

### VSCode extension ✅
Published on Open VSX. GitHub Releases (VSCode Marketplace unavailable from RF).

### Business / sales 🔜
one-pager → pilots (after S2) → payments (after S3).

---

## Already done (condensed)

- **Core v0.11 → v1.4.0:** PoC Auto-Generation, Exploit Chain Composer, Temporal Mutation Tracker, Invariant Engine, calibration 13/13, self-learning, MTTFV SLA, attack-graph, fix-quality, PoC watermarking, pre-commit.
- **Web3/Crypto:** GS041–GS044 + web3 SCA (Solidity SAST, crypto-secrets, honeypot, trading-bots).
- **Security:** internal audit 28/28 + AppSec DD-01..10 ✅, file pre-filter ✅.
- **Infrastructure:** Docker Compose, k8s manifests, FastAPI routers, SQL schemas, dashboard scaffold.

---

## Recommended plan

| Period | Focus | Outcome |
|---|---|---|
| Aug–Sep 2026 | Phase 8 (Precision) + S1/S2 + VSCode | GitHub App, 3–5 pilots |
| Oct–Dec 2026 | S3 + first payments | Private beta Cloud |
| Jan–Mar 2027 | S4 + Enterprise agent | Cloud 1.0 GA |
| Apr–Jun 2027 | Marketplace listings, growth | Traction → decision |

**Critical path:** Precision (Phase 8) → S1 → S2 → pilots → S3 → payments ≈ 3 months to first revenue.

---

## Risks

| Risk | Mitigation |
|---|---|
| Solo throughput | Strict phase sequencing |
| Precision CRIT ~5–10% | Phase 8 in progress (GS008/GS000-LEGACY being closed) |
| GHAS (CodeQL free for public) | AI-code niche + verified remediation, not «free SAST» |
| Competitors (Semgrep/Snyk) | Self-learning + PoC niche, PLG free-tier |
| LLM cost at scale | Global fingerprint cache, regex-first |
| SOC 2 cost | Defer until enterprise demand |
