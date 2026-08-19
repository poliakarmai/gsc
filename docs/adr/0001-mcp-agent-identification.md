# ADR-0001: Идентификация AI-агентов через MCP

- **Status:** Accepted
- **Date:** 2026-08-14
- **Deciders:** Алексей Поляков

## Контекст

`gsc_mcp_server.py` предоставляет AI-агентам (Claude, Cursor, Copilot и т.п.)
read-only инструменты поверх Model Context Protocol: `scan_repo`, `list_findings`,
`verify_finding`. Сейчас сервер работает через **stdio transport** (агент запускает
его как локальный subprocess на той же машине) и **без аутентификации**.

Вопрос: как идентифицировать AI-агента, подключающегося через MCP, и нужно ли это
вообще делать?

Ключевые факты:

- Деструктивные действия (`auto-patch`, PR, `feedback`) в MCP **не выведены** —
  они живут в CLI/REST под `GSC_API_KEY` (fail-closed, S-01).
- Feedback уже защищён от отравления на REST-уровне: per-IP rate-limit +
  audit-trail (A-06).
- Dashboard OAuth уже invite-only (S-08): открытого signup нет.
- MCP spec **не содержит встроенной аутентификации**; но клиент в `initialize`
  handshake отправляет `clientInfo {name, version}` — это бесплатный источник
  идентификатора агента.

## Решение

1. **Сейчас (stdio + read-only) — идентификацию НЕ вводим.**
   Локальный MCP-процесс запущен самим пользователем, чужого агента на этой
   границе нет: identity агента = identity процесса/пользователя, который его
   запустил. Аутентификация здесь не закрывает ни одной реальной угрозы — это
   мёртвый код. MCP остаётся **read-only** как главный рубеж.

2. **Идентификация становится обязательной при переходе на HTTP/SSE transport
   или multi-tenant** (Ф4 GitHub App + cloud S-трак). Тогда применяем два слоя:
   - **Auth (кто имеет доступ):** `Authorization: Bearer <API key>` на
     transport-уровне. Переиспользуем `GSC_API_KEY` (fail-closed, S-01) либо
     per-tenant key из `cloud/apideps.py`.
   - **Идентификация (какой агент, для аудита):** `clientInfo {name, version}`
     из MCP `initialize` handshake (`claude-code`, `cursor`, `codex`). FastMCP
     умеет его читать — пишем в audit-лог без кастомных заголовков.
   - **Tenant scope:** API key → `tenant_id`, каждый агент работает в границах
     своего тенанта (как в cloud API).

3. **Write-операции через MCP не открываем никогда.** Feedback, PR, auto-patch —
   только через REST/CLI с auth + audit-trail + rate-limit (A-06). MCP остаётся
   read-only навсегда.

## Последствия

**Положительные:**
- Минимальная поверхность атаки сейчас: read-only + stdio + локальный процесс.
- Чёткий триггер добавления auth: HTTP/SSE или multi-tenant — не раньше.
- Feedback poisoning (A-06) и открытый signup (S-08) закрыты независимо от MCP.

**Отрицательные / отложенная работа:**
- При HTTP/multi-tenant нужно будет реализовать Bearer-auth + `clientInfo`-логирование
  + per-tenant scoping. Осознанная отсрочка, а не пробел.

**Триггер активации:** первый коммит, выводящий MCP на HTTP/SSE transport или
multi-tenant доступ — обязан добавить auth по п.2 в том же PR.

## Связанные записи

- `docs/MCP_SERVER.md` — описание текущего MCP-сервера.
- `docs/SECURITY_FIX_REPORT.md` — S-01 (fail-closed key), A-06 (feedback poisoning),
  S-08 (invite-only onboarding).
- `cloud/user_auth.py`, `cloud/apideps.py` — tenant scoping / OAuth для cloud-трека.

## Реализация (2026-08-19)

Триггер активирован (вывод MCP на HTTP/SSE — Yandex AI Studio / cloud / multi-tenant):

- `gsc_cloud/gsc_mcp_auth.py` — `GSCMCPAuth` (FastMCP `TokenVerifier`): Bearer-токен →
  `tenant_id`; два режима — `GSC_MCP_TOKEN` (on-prem, constant-time) или `gsk_`-ключ
  через `auth_tenant` (cloud PG). Fail-closed: HTTP/SSE без сконфигурированного auth
  не стартует.
- `resolve_repo_path` + `GSC_ALLOWED_ROOTS` — path scoping для `scan_repo`/`verify_finding`
  (запрет выхода за разрешённые корни; symlink/`..` раскрываются через `realpath`).
- `--transport stdio|http|sse` в CLI.
- `tenant_id` + `client_id` агента прокидываются в `_audit` каждого ответа
  `scan_repo`/`verify_finding`.
- Тесты: `tests/test_mcp_auth.py` (17) + `test_scan_repo_rejects_outside_roots`.
