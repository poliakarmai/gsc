# Legal & IP Audit — GSC

> Дата: 13.08.2026. Юридический трек 0 (из внутреннего стратегического roadmap). Все проверки воспроизводимы.

## 1. Лицензия

**Dual license:** [Apache License 2.0](../LICENSE) (весь исходный код) + [Commercial](../COMMERCIAL.md)
(только для конкурирующего SaaS). Смена BSL → Apache 2.0 + Commercial выполнена 13.08.2026.

SPDX-заголовки синхронизированы: **77 файлов** переведены `BUSL-1.1` → `Apache-2.0`
(коммит `f982b62`). Проверка: `grep -rl "BUSL-1.1" --include="*.py" . | grep -v build/lib` → **0**.

## 2. Секреты в git-истории (gitleaks v8.21.2)

`gitleaks git` по всей истории (368 коммитов, 24s):

- **Найдено: 33 совпадения → 0 реальных секретов.**
- Классификация всех 19 уникальных значений:
  - placeholder-токены (`ghp_12...1234`, `sk-123...cdef`, `abc123def456`) — тестовые;
  - hash/fingerprint (SHA-256 finding_key/secret_fingerprint из scan-JSON) — не секреты;
  - UUID — не секреты;
  - публичный тестовый ключ youtube-dl (из `benchmark/real_world/youtube-dl_scan.json`);
  - `***` в `build/lib/` (вторичная копия, удаляется в repo-hygiene).

**Вывод:** реальных API-ключей/токенов/паролей в истории нет. Креденшелы (`TELEGRAM_BOT_TOKEN`,
`DEEPSEEK_API_KEY` и т.д.) читаются из env (`~/.hermes/.env`), в репозиторий не коммитятся.

## 3. Лицензии зависимостей

Все runtime-зависимости — permissive (MIT / Apache-2.0 / BSD). **GPL/LGPL/AGPL — нет.**

| Пакет | Лицензия |
|---|---|
| PyYAML | MIT |
| requests | Apache-2.0 |
| httpx | BSD-3-Clause |
| uvicorn | BSD-3-Clause |
| fastapi | MIT |
| pydantic | MIT |
| starlette | BSD-3-Clause |
| python-jose[cryptography] | MIT (cryptography: Apache-2.0 OR BSD-3-Clause) |
| stripe | MIT |
| Scrapy | BSD-3-Clause |
| click | BSD-3-Clause |
| pytest / pytest-cov / fakeredis (dev) | MIT / MIT / BSD |

## 4. Доказательства авторства (chain-of-title)

- **Первый коммит:** `2026-06-25 10:45:38 +0300` — `b89aae2` "GSC v0.1 — self-learning audit system".
- **Автор:** единственный — Alexey Polyakov `<armyanao@gmail.com>` (372 коммита, 100%).
- **История:** непрерывная с 25.06.2026 по 13.08.2026 (372 коммита), без чужих коммитов.

**Вывод:** чистый chain-of-title, единственный правообладатель — необходим для dual-лицензирования
и указан в CLA ([CONTRIBUTING.md](../CONTRIBUTING.md)).
