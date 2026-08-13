# PoC Verification Gap — измерение (Phase 0)

> Дата: 13.08.2026 | Метод: `scripts/gsc_poc_gap_measure.py` | Статус: **честный evidence для data-room**

## Методика

Для каждого проекта: scan → `attach_pocs` (deterministic + LLM) → для каждого PoC
`PoFSandbox._execute(poc, source, fmt)` → проверка success-маркера (`VULNERABLE`/`EXPLOITED`/…).

Три метрики: `findings_total` → `with_poc` → `poc_passed_marker`.

## Результат (10 real-world проектов, 160–132K ⭐)

| Проект | Findings | PoC | Passed |
|---|---|---|---|
| fastapi-users | 50 | 0 | 0 |
| flask-smorest | 4 | 0 | 0 |
| httpie | 131 | 2 | 0 |
| loguru | 19 | 1 | 0 |
| pendulum | 12 | 0 | 0 |
| piccolo-api | 101 | 1 | 0 |
| rich | 124 | 29 | 0 |
| sanic | 244 | 10 | 0 |
| thefuck | 123 | 1 | 0 |
| youtube-dl | 1840 | 11 | 0 |
| **ИТОГО** | **2648** | **55** | **0 (0%)** |

## Диагностика (два последовательных замера)

| Версия | Причина 0% passed | Статус |
|---|---|---|
| v1 | curl-PoC исполнялся как Python → `TypeError` (format-mismatch) | ✅ исправлено: fmt-dispatch |
| v2 | real_world проекты **multi-module** — HTTP-runner покрывает только single-file apps | ⚠️ ограничение Phase 2 |

## Что доказано

- ✅ **Format dispatch** работает: curl/bash PoC исполняются через bash, python через runner.
- ✅ **Phase 2 HTTP-runner** работает для **single-file** web apps (e2e: Flask `render_template_string`
  + curl `{{ 7 * 7 }}` → `VULNERABLE`).
- ✅ Deterministic PoC `_generate_code` → `curl -G --data-urlencode` (payload с пробелами/метасимволами).

## Ограничение (честно)

Real-world проекты (sanic 431 файл, fastapi-users, flask-smorest) — **multi-module**:
`target_code` — один файл без `app = Framework(...)`, поэтому `_detect_framework` не
поднимает сервер → curl-PoC возвращает `SAFE`.

**Вывод:** 0% passed — не «PoC галлюцинирует», а «runner не покрывает multi-module apps».

## Рекомендация

**Phase 3: multi-module app runner** — поднять весь проект (не один файл) как HTTP-сервер
в sandbox, с детектом entrypoint и зависимостей. Это закрывает 0% pass-rate и делает PoF
проверяемым на real-world коде.

Связано: `docs/EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md` (Runtime Validator, D→B→F),
`GSC_ROADMAP.md` Трек 0.6.
