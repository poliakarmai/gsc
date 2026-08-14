# KNOWN_LIMITATIONS.md — GSC

Честные ограничения текущей версии (v1.3.0). Обновляется при закрытии пунктов
(статус-трекинг: `docs/ROADMAP_MATURITY.md`).

## Покрытие языков

- **Python-first.** PoF-пайплайн (PoC-генерация, исполнение, верификация) полноценно
  работает для Python.
- JS/TS: SAST-детекторы есть, но авто-PoC и Proof-of-Fix для JS/TS — roadmap
  (не заявлены как работающие). Web PoC (curl/bash) покрывает HTTP-поверхность.

## Точность (precision)

- Первый замер на 10 реальных проектах: **CRITICAL precision ~8–12%** (до фикса
  GS001 extractor). Основной шум — GS001 на extractor/конфигах и тестовые секреты.
- Цифры точности зависят от ваших проектов. Проводите собственный замер
  (`benchmark/PRECISION_REPORT.md`), не полагайтесь на общие проценты.

## Верификация Proof-of-Fix

- `verified=True` выдаётся **только** при OS-изоляции (docker/podman).
- Без container runtime результат — `NOT verified` (fail-closed). rlimit/timeout
  **не являются** security boundary и не дают «verified».

## SCA / EPSS (data maturity)

- SCA (OSV.dev) и EPSS-кэш в текущей БД **пусты** — буст качества этих движков
  активируется только после накопления данных на реальных сканах. Функционально
  готовы, статистически не зрелы.

## Хранение и multi-tenant

- **SQLite** — dev/локальный контур, не concurrent multi-writer store.
- **PostgreSQL** (production) включается `GSC_DATABASE_URL`; enterprise-схема с
  RLS (`cloud/schema_s1.sql`) существует, но `server.py` runtime-контур пока не
  полностью объединён с `cloud/` enterprise-контуром (один onboarding, один
  storage backend — стратегический рефакторинг, не блокирует single-tenant pilot).

## Прочее

- **Calibration**: набор проектов для калибровки детекторов частично рассинхронизирован
  с документацией (14/17/19) — известный хвост, не критичный для pilot.
- **OpenAPI**: `docs/openapi.json` покрывает только `server.py` (SaaS MVP) — 14 endpoints.
- **SBOM/attestation**: генерация SBOM (CycloneDX/SPDX) и release-manifest есть, но
  полный signed-attestation цикл в CI — roadmap.
