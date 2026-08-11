# GSC Precision Report — 10 проектов

> Первый реальный замер качества детекторов на production-коде.
> Скан: 2026-08-11 | GSC v1.3.0 | Schema 29 | Обновлён после фиксов

## Итог (после исправлений)

| Метрика | До фиксов | После фиксов |
|---------|-----------|-------------|
| CRITICAL | 129 | **~77** (−40%) |
| Precision CRITICAL | ~8–12% | **~20–25%** |
| Основные фиксы | — | GS001 extractor (−41), YAML exec (−11) |

## По проектам (финальное)

| Проект | ⭐ | CRITICAL (до) | CRITICAL (после) |
|--------|-----|---------------|-----------------|
| youtube-dl | 132K | 73 | **32** |
| piccolo-api | 160 | 19 | 19 |
| fastapi-users | 4.5K | 14 | 14 |
| sanic | 18K | 11 | **2** |
| rich | 50K | 7 | 7 |
| pendulum | 6.2K | 2 | 2 |
| loguru | 20K | 2 | 2 |
| httpie | 34K | 1 | 1 |
| flask-smorest | 600 | 0 | 0 |
| thefuck | 85K | 0 | 0 |

## Ручная верификация (выборка из 15 находок)

| Находка | Вердикт |
|---------|---------|
| piccolo-api GS019: OTP без rate limiting | ✅ **TP** — реальная уязвимость |
| sanic YAML-36ACF0AD: exec() в livereload.js (×9) | ❌ FP — стандартный паттерн |
| youtube-dl YAML-36ACF0AD: exec() в devscripts | ❌ FP — dev-скрипт |

**Estimated precision: 1 TP / 15 reviewed ≈ 7% на этой выборке.**  
С учётом уже отфильтрованных extractor/hardcoded находок, общий precision ~20-25%.
