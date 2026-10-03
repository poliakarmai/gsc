# AGENTS.md — GSC для AI-агентов

GSC — SAST-сканер: 65 детекторов (SAST · SCA · Secrets · IaC), PoC (доказанный
эксплойт), Proof-of-Fix (верифицированный фикс), self-healing CI.

## Как подключить GSC

### Вариант A — GitHub Action (для репозиториев на GitHub)

Добавь `.github/workflows/gsc.yml`:

```yaml
name: GSC Audit
on:
  pull_request:
    branches: [main, master]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: poliakarmai/gsc@v1
        with:
          fail_on_critical: false
```

Скан запускается автоматически на каждый PR: комментарий с находками
(CRITICAL/HIGH) + JSON-отчёт. Опционально — BYO-LLM ключ для ревалидации
(`llm_api_key`).

### Вариант B — MCP (для Claude Code / Cursor / Codex / Hermes)

Read-only MCP-сервер, 6 инструментов:

- `scan_repo` — полный скан локального репозитория
- `scan_diff` — скан только изменённых файлов (PR-ревью)
- `list_findings` — недавние находки из БД
- `get_finding` — одна находка по ключу
- `verify_finding` — перезапуск PoC находки в sandbox
- `list_detectors` — список зарегистрированных детекторов

Транспорт: `stdio` (локальный subprocess, без auth) или `http`
(удалённый, требует `GSC_MCP_TOKEN`). Деструктивных действий (auto-patch/PR)
в MCP нет — они остаются в CLI/human-лупе.

## Лицензия

Этот репозиторий (Action + документация) = **Apache 2.0**. Движок
(docker-образ `ghcr.io/poliakarmai/gsc-scanner`) = **BSL 1.1** — сканировать
свои репозитории можно всегда; коммерческий SaaS/SAST-сервис в конкуренцию —
только по коммерческой лицензии. Change Date 2030-08-06 → движок переходит на Apache 2.0.
