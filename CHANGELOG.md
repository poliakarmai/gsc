# GSC Changelog

## Unreleased — 2026-08-13

### Roadmap maturity — волны A–D (2026-08-14)
- **Волна A** (security P1): header-only API key, JWT fail-closed, `StageOutcome`
  NOT_RUN/PASSED/FAILED, динамический подсчёт standalone, `/ready` probe.
- **Волна B** (isolation): web PoC container-first, security test suite (sandbox
  escape), request-scoped DB.
- **Волна C** (architecture): out-of-process worker, no import-time side effects,
  release manifest, pytest markers, conftest fixtures.
- **Волна D** (docs): `THREAT_MODEL.md`, `ARCHITECTURE.md`, `DEPLOYMENT.md`,
  `PILOT_GUIDE.md`, `KNOWN_LIMITATIONS.md`, `openapi.json`, «does NOT do» таблица.
- Due-diligence v2 (P0–P2 + шаги 4–6): immutable base image, SBOM, tenant-isolation
  тест, README disclosure про verification strength.

### License
- **BSL 1.1 → Apache 2.0 + Commercial dual** (`LICENSE` + `COMMERCIAL.md`)

### Killer Features
- **Supply-Chain Chain Composer** (`gsc_supply_chain_chains.py`) — связывает code flaws с reachable CVE через SBOM; CLI `gsc supply-chain`
- **Exploit Refinement Loop** (`gsc_exploit_refiner.py`) — feedback-driven PoC (RL-цикл: generate → execute → reward → refine)
- **Fixed 7 dead CLI commands** (`sca`, `sbom`, `epss`, `federated`, `iac`, `benchmark`, `sbom-verify`) via `args.func()` fallback

### Proof-of-Fix Sandbox (critical fix)
- **Format dispatch** — curl/bash PoC больше не исполняются как Python (был TypeError → 0% pass-rate)
- **Phase 2 HTTP-server runner** — single-file web targets поднимаются на localhost-порту, `TARGET_URL` подставляется; curl-PoC реально валидируются (e2e Flask SSTI → VULNERABLE)
- `_generate_code` → `curl -G --data-urlencode` (payload с пробелами/метасимволами доходит целым)

### Federated Privacy (экспертиза #2)
- **Step 1**: TLS-enforcement (https-only) + HMAC-SHA256 подпись payload
- **Step 2**: ротация `tenant_hash` (7-дневные эпохи) + privacy budget accounting (soft warn ε>5, hard stop ε>10)

### Distribution
- VSCode extension `poliakarmai.gsc-security v1.0.0` опубликован в **Open VSX** + **GitHub Releases** (VSCode Marketplace недоступен из РФ)

### Docs
- `EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md`, `EXPERTISE_02_FEDERATED_PRIVACY.md`
- `scripts/gsc_poc_gap_measure.py` — Phase 0 замер PoC-верификации

## v1.3.0 — 2026-08-07

### Architectural Cleanup
- **Unified detector contract**: `BaseDetector`, `RegexDetector`, `make_finding()` in `gsc_detectors/base.py`
- **All findings have rule_id**: 69/69 findings from legacy `check_source_driven`/`check_security` now carry `GS0xx` rule_id and stable `finding_key`
- **guard against empty rule_id**: `make_finding()` skips findings without rule_id (warn, don't crash)
- **IaC in gsc scan**: GS031 Dockerfile/Terraform/K8s detectors integrated into main `gsc scan` pipeline

### Detector Improvements
- **GS020 XSS f-string**: f-string/format()/template-literal HTML injection patterns
- **GS029 Secrets consolidation**: `gsc_secrets_core.py` — single source of patterns + fingerprint
- **Dead code removed**: `ORIGINAL_PATTERNS` in crossrepo, inverted PoF logic

### Quality
- **Calibration**: 10/10 projects (was 9/10 before IaC integration)
- **Tests**: 25/27 Python OK + 6 pipeline-refactor tests + 10/10 Enterprise + 7/7 VSCode
- **Metadata**: `gsc_meta.py` — single source of truth for detectors/schema/modules count
- **Docs synced**: PROJECT.md and AGENTS.md reference `gsc_meta.py` instead of hardcoded numbers

### New Tools
- `scripts/gsc_audit_detectors.py` — static + dynamic rule_id audit
- `gsc_secrets_core.py` — unified secrets patterns + fingerprint
- `gsc_meta.py` — dynamic metadata source
- `GSC_AUDIT_GUIDE.md` — AI-agent audit guide (entry points, invariants, quick checks)

### Known Issues
- SaaS S2–S3 not implemented (SKIP in tests)
- Enterprise on SQLite (designed for PostgreSQL)
- 26 legacy findings from grep-patterns now have `GS000-LEGACY` / derived rule_id — full migration to DETECTORS pending

---

## v1.2.0 — 2026-08-06

- Calibration 10/10 (GS020 f-string XSS working via plugin bridge)
- `gsc_crossrepo_secrets.py`: removed unused `ORIGINAL_PATTERNS`
- All dead code confirmed clean

## v1.1.1 — 2026-08-06

- IaC GS031 integrated into `cmd_scan` pipeline
- GS020 f-string XSS patterns added
- Calibration 9/10 (xss-demo — architectural gap: GS020 plugin vs scan pipeline)

## v1.1.0 — 2026-08-05

- Nuclei 7/7, VSCode 7/7, SaaS S1 5/5
- Enterprise 10/10: RBAC, SSO, Audit, Multi-tenancy, Helm
- AGENTS.md synced to v1.1

## v1.0.0 — 2026-08-04

- 28 plugin detectors + GS024 LLM
- Schema v28, SQLite, auto-migration
- Full cycle: detect → prove → fix → verify → heal → predict
- Calibration 8/10
