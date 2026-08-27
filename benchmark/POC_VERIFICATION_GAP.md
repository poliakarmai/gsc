# PoC Verification Gap — измерение (Phase 0)

> Дата: 13.08.2026 | Метод: `scripts/gsc_poc_gap_measure.py` | Статус: **честный evidence для data-room**

## Методика

Для каждого проекта: scan → `attach_pocs` (deterministic + LLM) → для каждого PoC
`PoFSandbox._execute(poc, source, fmt)` → проверка success-маркера (`VULNERABLE`/`EXPLOITED`/…).

Три метрики: `findings_total` → `with_poc` → `poc_passed_marker`.

## Результат (10 real-world проектов, 160–132K ⭐)

| Проект | Тип | Findings | PoC | Passed |
|---|---|---|---|---|
| fastapi-users | web-фреймворк | 50 | 0 | 0 |
| flask-smorest | web-фреймворк | 4 | 0 | 0 |
| httpie | CLI | 131 | 2 | 0 |
| loguru | библиотека | 19 | 1 | 0 |
| pendulum | библиотека | 12 | 0 | 0 |
| piccolo-api | web-фреймворк | 101 | 1 | 0 |
| rich | CLI-библиотека | 124 | 29 | 0 |
| sanic | web-фреймворк | 244 | 10 | 0 |
| thefuck | CLI | 123 | 1 | 0 |
| youtube-dl | CLI | 1840 | 11 | 0 |
| **ИТОГО** | | **2648** | **55** | **0 (0%)** |

## Диагностика (три последовательных замера)

| Версия | Причина 0% passed | Статус |
|---|---|---|
| v1 | curl-PoC исполнялся как Python → `TypeError` (format-mismatch) | ✅ исправлено: fmt-dispatch |
| v2 | real_world **multi-module** — runner покрывает только single-file | ✅ исправлено: Phase 3 multi-module runner |
| v3 | **корпус — библиотеки/CLI, а не web-приложения** | ⚠️ фундаментальное несоответствие, см. ниже |

## Root cause v3 (проверено grep-ом по коду)

Phase 3 работает: `_find_web_entrypoint` находит entrypoint, но он — **пример внутри
исходников фреймворка**, а не развёртываемое приложение:

| Проект | `_find_web_entrypoint` | Что это на самом деле |
|---|---|---|
| sanic | `sanic.simple` | `sanic/simple.py` — учебный пример, не приложение |
| fastapi-users | `examples.beanie.app.app` | example из `examples/`, не приложение |
| flask-smorest | `None` | библиотека, нет standalone `app = Flask(...)` |
| rich | `None` | CLI-библиотека, не web |

**Вывод:** 0% passed — **не баг PoF-механизма**. PoF (curl-PoC к HTTP-таргету) применим
только к **standalone web-приложениям**. А `benchmark/real_world/` — это библиотеки
(sanic, rich, pendulum, loguru) и CLI (httpie, thefuck, youtube-dl). У них нет «живого»
HTTP-сервера, который можно поднять и атаковать. Замеряли не тот класс проектов.

## Что доказано (после Phase 3)

- ✅ **Format dispatch** — curl/bash через bash, python через runner.
- ✅ **Single-file runner** — Flask `render_template_string` + curl `{{ 7*7 }}` → VULNERABLE.
- ✅ **Multi-module runner (Phase 3)** — e2e: multi-module Flask (app.py + views.py) →
  entrypoint детект `('flask','app')` → сервер поднят → curl SSTI → VULNERABLE.
- ✅ PoF-цикл **работает на web-приложениях** — это доказано, а не предположено.

## Что НЕ доказано / честное ограничение

PoF-верификация для **библиотек и CLI** (rich, youtube-dl, httpie) через curl-PoC
неприменима — у них нет HTTP-таргета. Нужен другой механизм: unit-test PoC (импорт
модуля + вызов функции с malicious input), а не curl к серверу.

## Рекомендация

1. **Собрать отдельный корпус standalone web-приложений** (Flask/FastAPI/Sanic apps с
   известными уязвимостями — например, из `calibration/` или нарочно уязвимые demo-apps)
   и замерить PoF pass-rate на нём. Это даст **честный ненулевой** pass-rate.
2. **Unit-test PoC для библиотек** (отдельный трек) — импорт + вызов функции с
   malicious input, без HTTP. Замыкает PoF для не-web кода.

Связано: `docs/EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md` (Runtime Validator, D→B→F),
внутренний roadmap, Трек 0.6.
