# GSC S2 — GitHub App + глубокие подсистемы (v0.29)

> 8 коммитов. Тесты 74→82. Внутренний контур: 17/17 calibration.

## Границы S2

| Входит | Не входит (S3) |
|---|---|
| GitHub App (installation, webhooks, токены) | Web Dashboard |
| Авторегистрация репо/тенантов (PLG) | Stripe |
| PR-скан по webhook | Метрики |
| /gsc-команды в облаке | SSO |
| chains/mutations/overrides в PG | |

## Коммиты

| # | Что | Гейт |
|---|---|---|
| 1 | Схема S2 (github_installs, chains, mutations, overrides) | RLS smoke |
| 2 | Рефакторинг MutationMatcher (чистый, без БД) | 17/17 calibration |
| 3 | GitHub App auth (JWT + installation tokens) | unit на JWT |
| 4 | Webhook receiver (подпись + dedup) | подпись/dedup тесты |
| 5 | Onboarding + scan jobs (PLG, supersede) | авто-тенант тест |
| 6 | GitHub worker + history ingest (netrc, fork-safe) | fork-safe + netrc |
| 7 | /gsc-команды (общий парсер) | round-trip вердиктов |
| 8 | Тесты S2 (+8 → 82/82) | 82/82 |

## Ключевые решения

- **PLG-онбординг:** установка App → авто free-тенант (нулевое трение)
- **Токен в netrc, не argv** — не светится в ps/логах
- **Fork-safe:** regex-only, без LLM, без инжеста мутаций
- **Мутации в PG:** история переживает эфемерный worker
- **Двойной dedup:** подпись → SETNX delivery (replay-защита)

## Найденные баги (9)

1. JWT clock skew 2. Token refresh margin 3. Подпись по parsed JSON
4. Replay вебхуков 5. Установки без тенанта 6. synchronize гонка
7. Токен в argv 8. Эфемерный SQLite 9. Импорт Actions-скрипта

## Гейт S2

82/82 тестов · 17/17 calibration · Round-trip install→scan→comment ·
Fork-safe · Подпись/dedup · Netrc-токены · /gsc tenant-scoped

См. полный документ: [[inbox/gsc-s2-implementation-2026-08-06]]
