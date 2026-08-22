# FP Classification — 10 реальных проектов

> Август 2026. 2695 находок, 41 детектор.

## Главные источники FP

### 🔴 CRITICAL (102 находки — наибольший риск)

| Detector | CRITICAL | Причина FP |
|----------|----------|-----------|
| GS001 | 47 | Extractor API keys: youtube-dl хардкодит токены в production — это ожидаемое поведение |
| GS025-hardcoded_[secret](https://github.com/poliakarmai/gsc/security/code-scanning/1) | 23 | Тестовые конфиги, примеры кода |
| YAML-36ACF0AD | 11 | exec() в livereload/devscripts — ✅ исправлен (CRITICAL→HIGH) |
| GS037-hardcoded_api_key | 9 | Примеры API-ключей в документации |
| GS037-hardcoded_password | 8 | Тестовые пароли |
| GS019 | 4 | Rate limiting — 1 реальный TP (OTP), 3 FP на health endpoints |

### 🟡 HIGH/MEDIUM (2593 находки — шум в отчётах)

| Detector | Всего | Причина |
|----------|-------|---------|
| GS022 | 1050 | Чрезмерно широкий детектор |
| GS000-LEGACY | 730 | Несвязанные legacy-паттерны |
| GS018 | 160 | Ложные срабатывания на тестовых файлах |
| GS025 | 125 | AI-детекция на конфигах |
| GS021 | 118 | Шум на файлах документации |
| GS003 | 55 | Debug-принты в легитимном коде |
| GS020 | 52 | XSS на sanitized-выводе |

## Категории FP по корневой причине

| Категория | % | Примеры |
|----------|-----|---------|
| Extractor/конфиг | 57% | youtube-dl, fastapi-users JWT secret |
| Тестовые файлы | 14% | pytest fixtures, unittest setUp |
| Слишком широкие паттерны | 12% | GS022, GS000-LEGACY |
| Нет sanitizer-проверки | 12% | XSS без escape, SQLi без taint |
| Реальные TP | 5% | GS019 OTP rate limiting |

## План снижения

| Приоритет | Действие | Детекторы |
|----------|---------|-----------|
| P0 | Exclude test/migrations/generated/docs | GS001, GS022, GS018 |
| P0 | Precision Gate (warn-only) | GS022, GS000-LEGACY, GS019 |
| P1 | Severity downgrade CRITICAL→HIGH | GS037-*, GS025-* |
| P1 | Контекстный sanitizer check | GS020 (XSS escape) |
| P2 | Пересмотр confidence | GS021, GS003 |

## 🔬 FP по benchmark 100 проектов (21.08.2026)

> 64 831 находка, 4 302 CRITICAL. После фильтрации шума (GS008 eval = 58% CRIT, GS000-LEGACY 26k)
> реальных кандидатов на PR — **ноль**: всё by-design сериализация, vendor-код или FP детектора.

### 2 новых FP-паттерна (для фикса детекторов)

| Detector | FP-паттерн | Пример | Фикс |
|----------|-----------|--------|------|
| GS037-yaml_unsafe_load | не распознаёт `yaml.load(..., SafeLoader)` | aws-cli `yamlhelper.py:99` (`SafeLoaderWrapper`), `ordered_yaml.py:47` (`SafeOrderedLoader`) | negation-guard: `yaml.load(x, SafeLoader*)` = безопасно |
| GS037-pickle_load_any | флагует by-design pickle (сериализация/кэш/ML) | celery `utils/serialization.py`, django `cache/backends/*`, scrapy `httpcache.py`, sklearn, streamlit | контекстный guard: pickle для доверенных данных (кеш/модели/сериализация) ≠ user input |

### Почему это by-design, а не уязвимость

- **pickle** опасен только при недоверенном input. celery/django-cache/scrapy/sklearn/streamlit
  сериализуют доверенные объекты (задачи, кеш, ML-модели) — документированное поведение.
- **yaml SafeLoader** (`yaml.load(x, SafeLoader)`) не выполняет произвольный код — FP детектора.

### Действия

| Приоритет | Действие |
|-----------|----------|
| P1 | Negation-guard для GS037-yaml_unsafe_load: распознавать `SafeLoader`/`SafeOrderedLoader` |
| P1 | Контекстный guard для GS037-pickle_load_any: исключать by-design паттерны (cache/сериализация/ML), либо downgrade |
