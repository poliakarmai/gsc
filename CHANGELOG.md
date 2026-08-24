# GSC Changelog

## Unreleased

### S1 Трек 2 — Workers out-of-process (2026-08-24)
- `gsc-worker` сервис в `docker-compose.yml`: демон `gsc_scan_worker.py --loop` поллит
  `scan_jobs` из PostgreSQL (без Redis), долгие clone+scan+store не висят на HTTP worker.
- `server.py::_run_scan` — при `GSC_WORKER_DAEMON=1` не спавнит per-scan процесс,
  только enqueue; демон единственный потребитель очереди.
- Починен баг пути в `gsc_scan_worker.py` (`_ROOT` → `_REPO_ROOT`, `gsc.py` искался
  в `gsc_cloud/` вместо корня репо).
- `gsc_cloud/workers.py` помечен LEGACY (использовал несуществующую таблицу `gsc_jobs`).

## v1.4.0 — 2026-08-19

### Новые фичи
- **SAST↔DAST correlation** — корреляция результатов SAST и DAST (в духе Solar
  appScreener): DAST-находка подтверждает SAST при совпадении класса и
  confidence ≥0.90 → `review_status='confirmed'` + `dast_evidence`. CLI `gsc correlate`.
- **Business-risk prioritisation** — приоритизация находок по бизнес-контексту
  (critical path × exploit-chain × EPSS), не только по CVSS. CLI `gsc business-risk`.
- **Dev security scorecard** — per-developer score через git-blame + статусы находок.
  CLI `gsc scorecard`.
- **Negation guards** — `pattern-not`/`not`/`not-patterns` в YAML-DSL (line-level
  подавление FP).
- **Trap corpus** — регресс-гард против FP на lookalike-но-безопасных сниппетах.

### Chore
- CI: `upload-artifact@v4` запинен на commit SHA (GSC-009).
- Версия → 1.4.0, 42 детектора, schema 33.

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

### Packages split (core/cli/cloud) — 2026-08-17
- **0.5.1** `gsc_core/` (13 модулей) — движок + детекторы (`gsc_db`, `gsc_blocking`, `gsc_detectors/`, `gsc_invariant_engine`, `gsc_compliance`, `gsc_sca`, `gsc_epss`, `gsc_federated`, `gsc_ast_dataflow`, `gsc_iac`, `gsc_secrets_core`, `gsc_yaml_rules`) → `78222dc`
- **0.5.2** `gsc_cli/` (51 модуль + `main.py`) — CLI + сканеры (orchestrator, external, github_adapter, poc_*, chain/exploit, proofoffix, selfhealing, archaeology, forecast, nlpolicy, nuclei, dast, sbom, spdx, revalidate, runtime_validator) → `e821e62`
- **0.5.3** `gsc_cloud/` (39 модулей) — SaaS API (api, api_v2, auth, billing, tenancy, sso, worker(s), scan_queue, marketplace, federated_server, mcp_server, pr_commands) → `b29af60`
- Корневые `gsc_*.py` — shim'ы (re-export через `sys.modules`) для обратной совместимости; `gsc_meta.py` — SSOT (169 модулей, 47 детекторов, schema 33)

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
- **Calibration**: 13/13 projects (9 clean + 4 vulnerable) — fixed scan hang on slow LLM (hard deadlines for revalidate/rejudge/PoC; new `ci`/`calibrate` scan-modes)
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
