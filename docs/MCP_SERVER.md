# GSC MCP Server — подключи свой ИИ-агент к сканеру безопасности

GSC умеет работать не только как CLI, но и как **MCP-сервер** — тогда любой
ИИ-агент (Claude Code, Cursor, Cline, Windsurf, Copilot) может сам запускать
сканирование, читать находки и верифицировать уязвимости **в своём контексте**,
без ручного запуска `gsc.py` и парсинга вывода.

---

## 1. Что это даёт

Вместо того чтобы копировать код в GSC вручную, агент получает три функции:

| Tool | Назначение |
|------|-----------|
| `scan_repo(repo_path, profile, scan_mode)` | прогоняет GSC по репозиторию → сводка + находки |
| `list_findings(limit, severity)` | читает последние находки из базы |
| `verify_finding(repo_path, finding_key)` | запускает PoC в песочнице → подтверждает, что уязвимость реально эксплуатируется |

Сценарий: агент клонирует репозиторий → `scan_repo` → получает уязвимости →
`verify_finding` подтверждает самые опасные → **чинит код сам** → пере-скан →
`scan-diff` показывает, что починилось. Полный цикл без человека.

---

## 2. Установка (для человека)

### 2.1 Зависимости

```bash
cd ~/gsc
pip install --break-system-packages mcp fastmcp   # на Debian/Ubuntu с PEP 668
# или просто: pip install mcp fastmcp
```

Проверка:

```bash
python3 gsc_mcp_server.py --help   # сервер стартует, ждёт stdio
```

### 2.2 Подключение к Claude Desktop

В файл `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
или `%APPDATA%\Claude\claude_desktop_config.json` (Windows) / `~/.config/Claude/claude_desktop_config.json` (Linux):

```json
{
  "mcpServers": {
    "gsc": {
      "command": "python3",
      "args": ["gsc_mcp_server.py"],
      "cwd": "/home/openclaw/gsc"
    }
  }
}
```

Перезапусти Claude Desktop → появится инструмент `gsc` с тремя функциями.

### 2.3 Подключение к Cursor

Создай `.cursor/mcp.json` в корне проекта (или глобально в настройках Cursor):

```json
{
  "mcpServers": {
    "gsc": {
      "command": "python3",
      "args": ["gsc_mcp_server.py"],
      "cwd": "/home/openclaw/gsc"
    }
  }
}
```

---

## 3. Использование (для человека)

Открой агента (Claude Desktop / Cursor) и попроси:

> «Просканируй репозиторий ~/my-project на уязвимости»

Агент сам вызовет `scan_repo`, покажет находки и предложит исправления.
Для подтверждения самых опасных:

> «Проверь, реально ли эксплуатируется находка <key>»

Агент вызовет `verify_finding` и вернёт результат PoC в песочнице.

---

## 4. Инструкция для ИИ-агентов

> Этот раздел написан для самого агента — он читается агентом при подключении.

### 4.1 Claude Code

Добавь в корень репозитория (или в `~/.claude.json` глобально) файл `.mcp.json`:

```json
{
  "mcpServers": {
    "gsc": {
      "command": "python3",
      "args": ["gsc_mcp_server.py"],
      "cwd": "/home/openclaw/gsc"
    }
  }
}
```

Затем `claude mcp list` — сервер `gsc` должен быть подключён.

### 4.2 Что агент должен знать

- **Ты получаешь 3 read-only инструмента**: `scan_repo`, `list_findings`, `verify_finding`.
- `scan_repo` принимает **локальный путь** к репозиторию (не URL). Сначала `git clone`, потом сканируй.
- `scan_repo` **дорогой** (LLM-ревалидация на DeepSeek/OLLAMA) — не вызывай в цикле, достаточно одного раза на репозиторий.
- `verify_finding` запускает PoC в **изолированной песочнице** (secret-free env + лимиты) — безопасно.
- **Деструктивных операций нет** (патч/PR остаются в CLI: `gsc.py pof generate --create-pr`). Ты только анализируешь и предлагаешь фиксы, человек применяет их или даёт тебе патчить код напрямую.

### 4.3 Пример сессии агента

```
User: просканируй ~/my-project и почини CRITICAL

Agent:
  1. scan_repo("~/my-project", profile="audit")
  2. → 3 CRITICAL: SQLi в app.py, SSTI в views.py, secret в config.py
  3. verify_finding("~/my-project", "<ssti-key>")
  4. → success=True, exploit работает → подтверждено
  5. правит views.py (экранирование шаблона)
  6. пере-скан → scan-diff показывает "fixed: 1"
```

---

## 5. Безопасность

- **Read-only** по дизайну: сервер не пишет файлы, не делает PR. Деструктив — только в CLI, осознанно.
- PoC выполняется в **изолированной песочнице** (`gsc_pof_sandbox`): secret-free окружение, лимиты ресурсов, таймауты.
- Ключи LLM (`DEEPSEEK_API_KEY` / `OLLAMA_BASE_URL`) читаются из `~/.hermes/.env` — **не** из сканируемого репозитория (S-07).

---

## 6. Troubleshooting

| Проблема | Решение |
|----------|---------|
| `No module named 'mcp'` | `pip install mcp fastmcp` |
| Сервер не появляется в агенте | проверь `cwd` — должен указывать на папку с `gsc_mcp_server.py` |
| `scan_repo` возвращает пусто | нет `DEEPSEEK_API_KEY` → LLM-этапы выключены (regex-only). Настрой ключ или локальный `OLLAMA_BASE_URL` |
| `verify_finding` → error | у находки нет PoC (детерминированный PoC генерируется только для части правил) |
