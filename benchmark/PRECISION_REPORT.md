# GSC Precision Report

## Замер 2 — 10 проектов ≤200⭐ (20.08.2026)

> Второй замер на свежем наборе из 10 проектов ≤200⭐ (4 known-TP + 6 clean).
> После precision-прохода 20.08: migration/test/prompt/context-фильтры + удаление
> синтетических агрегатов + сужение БД-паттернов.
> Скан: 2026-08-20 | GSC v1.4.0 | Schema 33

### Итог

| Метрика | До фиксов | После фиксов |
|---------|-----------|-------------|
| CRITICAL (severity) | 54 | **1** |
| FP среди CRITICAL | 53 | **0** |
| Recall (known-TP) | 4/4 | **4/4** |
| Precision CRITICAL | ~2% | **~50%** (1 TP / 2, n мал — не репрезентативно) |

### Закрытые FP-классы (9)

| Класс | Пример | Детектор |
|-------|--------|----------|
| SQL в миграциях | `migrations/versions/*.py` — `.format()` на константах | GS005 + БД-паттерны |
| Тестовые пароли | `password='abcd'` в `tests.py` | GS001 |
| `input()`/`getpass()` prompt | `input("Password: ")` | GS001 |
| `time.sleep()` как blind SQLi | `sleep(` для rate-limit | GS005 |
| Internal dev hosts | `redis://cache:6379`, `sqlite:///…` | GS001 |
| hCaptcha test-keys | `0x0000…`, `10000000-…` | GS025 |
| abstract OTP | `@abstractmethod send_code` | GS019 |
| Enum-роль как creds | `ADMIN = "admin"` в `class X(Enum)` | GS017 |
| Tutorial/provision SUID | `chmod` в `provision.sh` | GS016 / GS032 / БД |

### По проектам (CRITICAL severity)

| Проект | ⭐ | CRITICAL (до) | CRITICAL (после) |
|--------|-----|---------------|-----------------|
| aiohttp-security | 147 | 0 | 0 |
| django-ca | 158 | 8 | 0 |
| Baobab | 60 | 40 | **1 (TP)** |
| cyberbro | 122 | 3 | 0 |
| piccolo-api | 161 | 8 | 0 |
| python-sdk | 73 | 1 | 0 |
| dagster-authkit | 62 | 4 | 0 |
| grocery-app | 46 | 1 | 0 |
| MCGJ | 33 | 2 | 0 |
| CPA-X | 62 | 3 | 0 |

### Единственный оставшийся CRITICAL (TP)

- Baobab `api/app/invoice/generator.py:12` — `API_KEY = 'sk_Lex…'` (реальный Stripe secret key).

> **Честная оговорка:** «0 FP» на 10 проектах — это 1 TP из 2 CRITICAL-кандидатов
> (n слишком мал для статистики). Known-TP на aiohttp-security/django-ca/cyberbro
> детектятся как HIGH/MEDIUM (Session Fixation, SSRF, XSS) — recall сохранён, но
> severity частично понижен. Прежде чем заявлять «~50% precision», нужен замер на
> ≥100 проектах (track 0.14.2 в GSC_ROADMAP.md).

---

## Замер 1 — 10 проектов (11.08.2026)

> Первый реальный замер на production-коде (160–132K ⭐).
> Скан: 2026-08-11 | GSC v1.3.0 | Schema 29

| Метрика | До фиксов | После фиксов |
|---------|-----------|-------------|
| CRITICAL | 129 | **~77** (−40%) |
| Precision CRITICAL | ~8–12% | **~20–25%** |
| Основные фиксы | — | GS001 extractor (−41), YAML exec (−11) |

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
