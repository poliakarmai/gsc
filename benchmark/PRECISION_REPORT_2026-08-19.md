# GSC Precision Report — Calibration (13 projects) + fresh repos

> Замер 2026-08-19 | GSC v1.3.0 | Schema 32 | скрипт `scripts/gsc_precision_measure.py`
> Ground truth: `calibration/calibration_dataset.json` (9 clean + 4 vulnerable).

## Метод

- **Clean-проект** (9): любая находка = FP по определению. Считаем FP по `rule_id`.
- **Vulnerable-проект** (4): сверяем recall по `expected_vulns` (маппинг тип→rule_id).
- Плюс 2 свежих zero-star проекта (`quant-vectorized-backtester`, `explain-back-tutor`).

## Clean-проекты: FP по детекторам (539 total)

| Detector | FP | Share |
|----------|----:|------:|
| **GS000-LEGACY** | **330** | **61%** |
| GS021 (CSRF/SSRF) | 39 | 7% |
| GS020 (XSS) | 33 | 6% |
| GS037 (path-traversal variants) | 21 | 4% |
| GS003 (debug prints) | 14 | 3% |
| GS022 (open redirect) | 14 | 3% |
| GS009 (supply chain) | 9 | 2% |
| GS008 / GS005 / GS025 / YAML-36ACF0AD / GS015 | 8 each | 1.5% |
| прочие | 39 | 7% |

## Внутри GS000-LEGACY (330 FP)

| Title | FP |
|-------|----:|
| `Python: assert in production` | 144 |
| `Generic code smell #NN` | ~30 |
| `CVE-2026-XXXXX: Path traversal / Buffer overflow / …` | ~5 |
| `Хардкод IP адреса` | ~3 |
| `World-readable file: … (664)` | ~4 |

Источники: `python_patterns` (main.py:1563), `CVE_PATTERN_MAP` (`_cron_collect.py`, пустой
detector), `_perm_finding()` (echelon-2), автосгенерированные code-smell паттерны.

## Vulnerable-проекты: recall (expected_vulns)

| Тип | Результат |
|-----|-----------|
| xss | 2/2 ✅ |
| command_injection | 1/1 ✅ |
| sql_injection | 2/3 ⚠️ (dvpwa — miss) |
| hardcoded_secret | 0/1 ❌ (flask-jwt-auth — miss) |
| idor | 0/1 ❌ (pygoat — miss) |

**Recall: 5/8 = 62.5%.** Три дыры: hardcoded-secret (flask-jwt-auth), SQLi (dvpwa), IDOR (pygoat).

## Выводы

1. **GS000-LEGACY = 61% шума** — главная цель precision-работы. Бриф: `docs/DETECTOR_BRIEF_GS000_LEGACY.md`.
2. После GS000-LEGACY: **GS021 (39)**, **GS020 (33)**, **GS037 path-traversal (21)** — вторые по шуму.
3. **Recall-дыры** (hardcoded_secret, SQLi dvpwa, IDOR) — отдельный трек, не precision.

## Действия

- [x] GS020 SSTI const-skip (`a38326d`) + A09 print-спам убран.
- [x] Бриф GS000-LEGACY готов для внешнего агента.
- [ ] GS000-LEGACY precision-pass (assert/code-smell/NVD-CVE) — по брифу.
- [ ] Recall-дыры: GS001 (hardcoded secret), GS005 (SQLi), GS007 (IDOR).
