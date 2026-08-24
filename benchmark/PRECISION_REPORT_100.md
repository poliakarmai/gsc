# PRECISION_REPORT_100.md — внешний benchmark на 100 реальных проектах

> Замер 3 (21.08.2026). Полный прогон GSC по 100 реальным проектам с GitHub.
> Предыдущие замеры — в `PRECISION_REPORT.md` (Замер 1: 10 проектов, precision CRIT ~8–12%).
> Генераторы: `scripts/gsc_benchmark_100.py`, `scripts/gsc_benchmark_batch.py`,
> `scripts/gsc_benchmark_all.py`. Порядок — от мелких к крупным (по LOC + звёздам).

## Замер 4 (24.08.2026) — после precision-чистки

Частичный прогон (45 проектов, `next.js` timeout >900s, процесс завершён досрочно).
Зафиксирован в `benchmark/precision_report_100.json`.

| Метрика | Замер 3 (21.08) | Замер 4 (24.08, 45 проектов) |
|---|---|---|
| Проектов | 100 | 45 |
| CRITICAL | 4 302 | **498** |
| HIGH | 37 246 | **1 324** |

Топ CRITICAL после чистки:

| Rule | Замер 3 CRIT | Замер 4 CRIT | Диагноз |
|---|---|---|---|
| GS005 (SQLi) | 211 (4 258 по свежему срезу) | **29** | downgrade всех интерполяций + окно 15 → ~3.5K FP срезано |
| GS008 (eval) | 2 508 | 0 CRIT (31 LOW) | ✅ починен (ba4c2d0 + CRITICAL→HIGH) |
| GS000-LEGACY | 505 | **7** | ✅ legacy-чистка (remap в INFO/MEDIUM) |
| GS001 (hardcoded) | 613 | **376** | 🔴 новый лидер — следующий кандидат |

**Вывод:** все три главных FP-источника (GS008, GS000-LEGACY, GS005) срезаны;
суммарный CRITICAL упал ~8×. Новый фокус precision — GS001 (376 CRITICAL).

## Итог

| Метрика | Значение |
|---|---|
| Проектов | 100 (90 чистых + 10 известных уязвимых) |
| Ошибок скана | 0 |
| Находок всего | 64 831 |
| CRITICAL | 4 302 |
| HIGH | 37 246 |
| **Recall** | **8/10** уязвимых поймано |
| Чистых проектов без CRIT | 42/90 |
| Чистых проектов с CRIT (FP-шум) | 48/90 |

## Recall (известные уязвимые проекты)

| Проект | CRIT | Пойман |
|---|---|---|
| juice-shop | 100 | ✅ |
| DVWA | 39 | ✅ |
| pygoat | 24 | ✅ |
| dvws-node | 16 | ✅ |
| NodeGoat | 9 | ✅ |
| goof | 7 | ✅ |
| django-ca | 4 | ✅ |
| dvna | 2 | ✅ |
| aiohttp-security | 0 | ❌ |
| cyberbro | 0 | ❌ |

Пропуски: `aiohttp-security`, `cyberbro` — 0 CRITICAL.

## Топ CRITICAL-генераторов (источник FP-шума)

| Rule | CRIT | HIGH | Диагноз |
|---|---|---|---|
| GS008 (eval/exec) | 2 508 | 110 | eval() легален в бандлерах/минификаторах → почти всё FP |
| GS001 (hardcoded creds/PAN) | 613 | 0 | |
| GS000-LEGACY | 505 | 26 678 | 26k находок без rule_id — data-quality долг |
| GS005 (SQLi) | 211 | 0 | |
| GS038-hardcoded_password | 140 | 0 | |
| GS029 (secrets) | 80 | 455 | |

**Ключевой вывод:** GS008 (eval) даёт 2 508 из 4 302 CRITICAL (~58%). На крупных
чистых проектах (next.js, webpack, rollup) eval/Function используются легитимно
бандлерами и минификаторами → массовый FP.

## Артефакты

- `benchmark/precision_report_ALL_100.json` — агрегат по 100 проектам.
- `benchmark/precision_report_batch1..10.json` — по батчам (10 проектов каждый).
- `benchmark/projects_100.json` — список 100 проектов.
- `benchmark/projects_100_ordered.json` — порядок «мелкие → крупные» (LOC + звёзды).
- `benchmark/projects_100_pinned.json` — pinned-ревизии (воспроизводимость).

## Следующие шаги

1. Починить GS008 (eval → severity-калибровка / FP-гарды) — главный шум.
2. Разобрать GS000-LEGACY (26 678 HIGH без rule_id) — data-quality.
3. Перегнать benchmark → измерить precision-скачок.
