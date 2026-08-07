# GSC Changelog

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
