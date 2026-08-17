# GSC Bot — GitHub App для виральной верификации чужих PR

> Трек 0.8 | Статус: спроектирован (17.08.2026) | Оценка: ~2 недели, можно ДО S1
> Переиспользует: `gsc_cli/gsc_signature.py` (готово), `gsc_cli/gsc_github_adapter.py` (готово),
> `gsc_cli/gsc_selfhealing.py` (готово), `gsc_cloud/pr_commands.py` + `gsc_cloud/webhook.py` (scaffold).

## Цель (one-liner)

GitHub App `gsc-bot`, который приходит на **чужой** PR по вызову (`@gsc` / `/gsc ...`) и оставляет
узнаваемую плашку GSC — badge + отчёт + label `gsc-verified` + check-run. Каждый такой PR =
бесплатная реклама GSC в чужом репозитории.

## Проблема

Подпись GSC сейчас привязана к артефактам, которые GSC создаёт **сам** (`pof batch --create-pr`,
PoF-отчёт, комментарий гейта). Сторонний агент (Claude Code, Codex, любой AI-кодер), использующий
GSC как локальный сканер, делает PR своими руками — плашки нет. Канал виральности ограничен нашим
собственным self-healing. Нужен канал, где GSC приходит НА чужой PR по явному вызову.

## Решение

`gsc-bot` — GitHub App, подписывающий чужие PR по явному вызову:

| Команда | Действие | Результат |
|---|---|---|
| `@gsc scan` / `/gsc scan` | сканирует diff PR (или репозиторий) | комментарий `🔍 Scanned by GSC` + badge + отчёт |
| `@gsc verify` / `/gsc verify` | прогон Proof-of-Fix по изменениям | label `gsc-verified` (только при verified) + check-run |
| `/gsc label` | ручная постановка label | label `gsc-verified` |
| авто-триггер (опц., 0.8.5) | PR с AI-сигнатурой (`Generated with …`, `🤖`) | комментарий-предложение `@gsc scan` |

## Сценарии

1. **Агент фиксит уязвимость и хочет доказательство.** Пишет в своём PR `@gsc verify` → GSC сканирует,
   гонит PoF в sandbox, ставит `gsc-verified` + check-run green → ревьюер видит «проверено GSC».
2. **Агент просто сканирует.** `@gsc scan` → отчёт в комментарии с плашкой.
3. **Авто-детект.** PR-описание содержит `🤖 Generated with Claude Code` → бот предлагает `@gsc scan`.

## Архитектура

Нового — только webhook-сервер; вся бизнес-логика переиспользуется:

```
GitHub PR (чужой репо)
   │ issue_comment / pull_request event
   ▼
gsc_cloud/github_app.py   (webhook endpoint, HMAC-верификация, installation token)
   │
   ├─ /gsc scan ──► gsc_cli/gsc_github_adapter.py (upsert_comment + create_check_run)
   │                + gsc_cli/gsc_signature.py (comment_signature + badge_markdown)
   │
   ├─ /gsc verify ─► gsc_cli/gsc_selfhealing.py (pof batch, sandbox)
   │                + gsc_cli/gsc_signature.py (label_name → gsc-verified)
   │
   └─ co-author ──► gsc_cli/gsc_signature.py (co_author_trailer — сейчас no-op)
```

**Уже готово (НЕ переделывать):**
- `gsc_cli/gsc_signature.py` — все подписи/badge/label/trailer.
- `gsc_cli/gsc_github_adapter.py` — `upsert_comment()`, `create_check_run()`.
- `gsc_cli/gsc_selfhealing.py` — `pof batch` + PoF-верификация.
- `gsc_cloud/pr_commands.py`, `gsc_cloud/webhook.py` — scaffold slash-команд/webhook.

**Новое:**
- `gsc_cloud/github_app.py` — FastAPI endpoint + HMAC + installation auth.
- GitHub App манифест + private key (age-шифрование).
- Docker-деплой (переиспользовать `cloud/Dockerfile`).

## Фазы (0.8.x)

| # | Фаза | Содержание | Проверка |
|---|---|---|---|
| 0.8.1 | App scaffold | манифест, webhook endpoint, HMAC-верификация, installation token exchange, обработка `issue_comment`/`pull_request` | webhook принимает тестовый event, неверный HMAC → 401 |
| 0.8.2 | `/gsc scan` | diff-скан → комментарий с badge + отчётом (adapter + signature) | `@gsc scan` в чужом PR → комментарий < 30 сек |
| 0.8.3 | `/gsc verify` | PoF по изменениям → label `gsc-verified` (только verified) + check-run | label только при verified; иначе check-run neutral |
| 0.8.4 | co-author | `co_author_trailer()` активируется: `Co-authored-by: gsc-bot[bot]` | трейлер линкуется GitHub'ом |
| 0.8.5 | авто-детект | парсинг PR body на AI-сигнатуры → предложение `@gsc scan` | PR от Claude Code/Codex → предложение |

## Безопасность (обязательно, не после факта)

- **HMAC-верификация webhook** (`X-Hub-Signature-256`) — иначе любой дёргает бота.
- **installation token** short-lived (60 мин), per-repo permissions.
- **Permissions (least-privilege):** `contents: read`, `pull-requests: write`, `issues: write`,
  `checks: write`. БЕЗ `contents: write` (бот не пушит в чужие ветки).
- **Fork-код не исполняется с привилегиями:** сканирование — static (read), PoF — в sandbox
  (`--network none --read-only --cap-drop ALL --user 65534`, уже есть).
- **Rate-limit:** GitHub App 5000 req/h — достаточно; per-repo cache по fingerprint.
- **Private key** — age-шифрование в `.env` (recipient из `~/.hermes/age-key.txt`), НЕ в git.

## Критерии приёмки (Definition of Done)

- [ ] `@gsc scan` в чужом PR → комментарий с badge + отчётом < 30 сек.
- [ ] `/gsc verify` на уязвимом diff → `gsc-verified` ТОЛЬКО при verified PoF.
- [ ] check-run отражается в Checks UI.
- [ ] Fork-код не исполняется с привилегиями (static + sandbox).
- [ ] Webhook-подпись проверяется (неверный HMAC → 401).
- [ ] Private key не в git (age-шифрован).
- [ ] `co_author_trailer()` реально линкуется (после создания App).

## Не-цели

- ❌ Авто-скан ВСЕХ PR без вызова (шум + LLM-расходы). Только по `@gsc`/явному триггеру.
- ❌ Git push/commit в чужие репозитории (бот read-only + write в comments/checks только).
- ❌ Замена self-healing (тот создаёт PR от имени GSC; бот — комментирует/верифицирует чужие).
- ❌ Multi-tenant SaaS-инфраструктура (это S1/S2, PG/RLS).

## Связь с другими треками

- **S2 (GitHub App, SaaS):** S2 делает GitHub App как часть SaaS (install/webhooks, PG, `/gsc` в
  SaaS-контексте). Трек 0.8 — минимальный **standalone** App для виральности, можно запустить ДО S1
  (SQLite, self-hosted). S2 затем поглощает 0.8 (multi-tenant поверх).
- **Трек 0.7.6 (benchmark):** `@gsc verify` даёт реальные PR-кейсы для доказательств продаж.
- **gsc-signature (закрыт 17.08):** 0.8 активирует no-op `co_author_trailer()`.

## Метрики успеха

- N репозиториев, где `@gsc` вызван в PR (установки App).
- Доля PR с `gsc-verified`, принятых ревьюерами быстрее.
- Входящий трафик на репо через badge-ссылки (referral).

## Риски

| Риск | Митигация |
|---|---|
| Webhook-подпись не проверяется | HMAC обязателен с 0.8.1 |
| Spam `@gsc` на чужих PR | rate-limit + только на PR, где App установлен |
| LLM-расходы на verify | cache по fingerprint + regex-first + суточный лимит |
| GitHub App approval (публичная регистрация) | старт private/self-hosted, публично — позже |
