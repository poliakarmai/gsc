# GSC_APPLY_PLAN.md — v0.17 → v0.26

Единый порядок применения (31 коммит). Правило: каждый коммит оставляет CI зелёным.

**Гейты:** T=тесты, C=calibration, S=schema.
**Откат:** по скорости: конфиг-флаг → git revert → DB restore.

| # | Коммит | Версия | Гейт | Откат |
|---|---|---|---|---|
| 1 | feat(detectors): GS025 AI-code provenance | v0.17 | T | убрать из реестра |
| 2 | feat(poc): PoC generator + redaction gate | v0.17 | T | poc_generation.enabled: false |
| 3 | ci(calibration): ai-generated-demo | v0.17 | C 15/15 | убрать из dataset |
| 4 | feat(chains): chain composer | v0.18 | T | chains.enabled: false |
| 5 | feat(db): migration 18 — chains + feedback | v0.18 | S=18 | restore .bak-v018-* |
| 6 | feat(github): chains in comment + SARIF | v0.18 | smoke | revert |
| 7 | ci(calibration): vuln-chain-demo, soft assert | v0.18 | C 16/16 | remove project |
| 8 | feat(mutations): tracker + migration 19 | v0.19 | T, S=19 | mutation_tracking.enabled: false |
| 9 | chore(db): backfill fingerprints 400K | v0.19 | backfill 100% | идемпотентен |
| 10 | feat(nightly): auto-resolve in self-learning | v0.19 | T | flag off |
| 11 | feat(invariants): engine + GS028 + safe_mode | v0.20 | T | invariants_enabled: false |
| 12 | ci(calibration): vuln-invariant-demo | v0.20 | C 17/17 | remove project |
| 13 | feat(ast): python taint tracking | v0.21 | T | ast_dataflow: false |
| 14 | feat(chains): cross-file candidates | v0.21 | T | chains.cross_file: false |
| 15 | ci(calibration): hard chain assert 2/3 + release v0.21 | v0.21 | C hard | revert to soft |
| 16 | feat(scan): dry-run contract + would_block | v0.22 | T | revert |
| 17 | feat(ci): gsc-dry-run.yml + redact/summary + migration 20 + /api/v1/dryrun | v0.22 | S=20, >=20 PR dry-run | remove workflow |
| 18 | feat(adapter): phase-aware conclusion + priority truncation | v0.23 | T | revert |
| 19 | feat(db): migration 21 — publications/reactions | v0.23 | S=21 | restore |
| 20 | feat(ci): internal-pr publish + reactions nightly | v0.23 | 15 PR, 0 incidents | revert to --dry-run |
| 21 | feat(db): migration 22 — feedback source/actor | v0.24 | S=22 | restore |
| 22 | feat(api): /api/v1/feedback + stats | v0.24 | T | revert |
| 23 | feat(ci): gsc-feedback.yml + /gsc parser | v0.24 | round-trip | remove workflow |
| 24 | feat(metrics): --detectors TP dashboard + footer | v0.24 | >=30 verdicts | revert |
| 25 | feat(blocking): BlockingEngine + auto policy | v0.25 | T | rollout_phase: warn-only |
| 26 | feat(db): migration 23 — overrides | v0.25 | S=23 | restore |
| 27 | feat(api): /api/v1/overrides + /gsc override | v0.25 | round-trip | revert |
| 28 | feat(ci): fail-on-blocking + bypass label + shadow week | v0.25 | shadow FP-review | shadow: true |
| 29 | feat(blocking): chain blocking + poc_boost | v0.26 | T 67/67 | poc_boost: false |
| 30 | feat(metrics): phase5 stats + rollout report | v0.26 | report green | revert |
| 31 | docs: PROJECT.md v1.0 + rollout complete | v0.26 | — | — |

## Иерархия отката (по скорости)

1. **Конфиг-флаг** — любая фича отключается в `.gsc-audit.yml`/профилях мгновенно
2. **git revert** — коммиты атомарны, каждый ревертится независимо
3. **DB restore** — только для v0.18/v0.19; backup'ы создаются автоматически

## Обязательные backup'ы

```
pre-v017, v018, v019, pre-phase1 (20), pre-phase2 (21),
pre-phase3 (22), pre-phase4 (23)
```
