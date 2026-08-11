# GSC Precision Report — 10 проектов

> Первый реальный замер качества детекторов на production-коде.
> Скан: 2026-08-11 | GSC v1.3.0 | Schema 29

## Итог

| Метрика | Значение |
|---------|----------|
| Проектов | 10 (160–132 000 ⭐) |
| Всего находок | 2 695 |
| CRITICAL | 129 |
| HIGH | 244 |
| Время скана | 268s (4.5 мин) |

## По проектам

| Проект | ⭐ | Всего | CRITICAL | HIGH | Время |
|--------|-----|-------|----------|------|-------|
| flask-smorest | 600 | 4 | 0 | 3 | 7.9s |
| fastapi-users | 4 500 | 50 | 14 | 5 | 10.1s |
| piccolo-api | 160 | 106 | 19 | 24 | 15.7s |
| sanic | 18 000 | 243 | 11 | 50 | 38.4s |
| httpie | 34 000 | 131 | 1 | 10 | 13.9s |
| thefuck | 85 000 | 123 | 0 | 101 | 12.5s |
| **youtube-dl** | **132 000** | **1 884** | **73** | 25 | 99.2s |
| pendulum | 6 200 | 12 | 2 | 2 | 14.7s |
| loguru | 20 000 | 19 | 2 | 10 | 10.4s |
| rich | 50 000 | 123 | 7 | 14 | 45.0s |

## CRITICAL по детекторам

| Rule | Кол-во | Оценка |
|------|--------|--------|
| GS001 (hardcoded secrets) | 47 | ~90% FP — extractor keys, test tokens |
| GS025/GSAUTO (hardcoded) | 34 | ~95% FP — тестовые значения |
| GS005 (SQL injection) | 11 | требует ручной проверки |
| GS029 (cross-repo secrets) | 11 | требует ручной проверки |
| YAML (custom rules) | 11 | требует ручной проверки |
| GS007 (IDOR/BAC) | 2 | вероятно FP |
| GS019 (auth/session) | 4 | требует ручной проверки |
| Прочие | 9 | |

## Предварительный вывод

Из 129 CRITICAL:
- **Явные FP**: ~60-70 (GS001/GS025 hardcoded secrets в extractors/тестах)
- **Спорные**: ~40-50 (GS005 SQLi, GS029 secrets — нужна ручная верификация)
- **Вероятные TP**: ~10-15

**Estimated precision на CRITICAL: 8-12%**. Это не плохо для SAST (Semgrep даёт ~5-15% на незнакомом коде), но требует ручной верификации и улучшения шумоподавления для GS001/GS025.

## Известные источники шума

1. **GS001:** срабатывает на API-токены в extractor'ах (youtube-dl) — это expected behaviour, не уязвимость
2. **GS025/GSAUTO:** hardcoded секреты в тестовых файлах и конфигах
3. **GS005:** f-string в SQLAlchemy text() без реальной инъекции (ORM оборачивает)

## Что дальше

- [ ] Ручная верификация всех 129 CRITICAL → точный precision
- [ ] OWASP Benchmark Suite прогон → recall
- [ ] Подавление GS001 на extractor-паттернах
- [ ] GS005: downgrade` text(f"...")` без taint source до MEDIUM
