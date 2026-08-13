# Enterprise Hardening — GSC

> Дата: 13.08.2026. Трек 0.7.7 (Sale-Readiness). Каждое утверждение сверено с кодом (grep).

Этот документ отвечает на стандартные вопросы due-diligence покупателя: что выходит за пределы
машины (egress), как изолирован PoC-рантайм, где обрабатывается код/данные при LLM-ревалидации.

## 1. Threat model (кратко)

Доверительные границы:

| Граница | Компонент | Модель угрозы |
|---|---|---|
| Хост → PoC-рантайм | `gsc_pof_sandbox.py`, `gsc_proofoffix.py` | Вредоносный PoC пытается выйти в сеть / исчерпать ресурсы |
| Код → LLM | `gsc_llm_providers.py`, `gsc_revalidate.py` | Утечка кода клиента третьей стороне |
| Агент → GSC | `gsc_mcp_server.py` | Агент-ИИ инициирует деструктивные действия |

## 2. Egress policy (что выходит наружу)

### PoC-рантайм — изолирован, сети нет

- `NO_NET_ENV` (`gsc_proofoffix.py:37`): `http_proxy`/`https_proxy`/`HTTP_PROXY`/`HTTPS_PROXY`
  указывают на `http://127.0.0.1:9` (port 9 = discard), `no_proxy=""`. **Любой сетевой вызов PoC
  немедленно падает** — exfiltration/SSRF из сгенерированного PoC невозможен по построению.
- `resource.setrlimit` (`gsc_pof_sandbox.py:121–124`): `RLIMIT_CPU` (таймаут), `RLIMIT_AS`
  (лимит памяти), `RLIMIT_NPROC` (64), `RLIMIT_FSIZE`. Fork-бомбы / memory-бомбы ограничены.

### Исходящий трафик самого сканера

- SCA (`gsc_sca.py`) → OSV.dev API (только CVE-запросы, без кода клиента).
- LLM-ревалидация → `gsc_llm_providers.py` (см. §3).

## 3. LLM retention / data-residency

Единый слой `gsc_llm_providers.llm_chat()` (`gsc_llm_providers.py`):

- **No-LLM режим по умолчанию при отсутствии ключей** — все детекторы деградируют до
  regex-only (`llm_chat` возвращает `None` → авто-деградация).
- **Airgap/on-prem:** локальные провайдеры OLLAMA (`OLLAMA_BASE_URL`) и LM Studio
  (`LMSTUDIO_BASE_URL`) — код не покидает контур заказчика. Подключаются **только при явной
  конфигурации** (не блокируют failover на недоступный localhost по умолчанию).
- **Внешние провайдеры** (DeepSeek/OpenRouter) — включаются только через env-ключи
  (`DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`), никогда не хардкодятся (S-07).
- **Что отправляется LLM:** изолированный сниппет/признаки finding для ревалидации, не весь
  репозиторий. Значения секретов **не хранятся** — только fingerprint (инвариант 6).

## 4. MCP — read-only

`gsc_mcp_server.py` экспонирует только `scan_repo`, `list_findings`, `verify_finding`.
Деструктивные действия (patch/PR/блокировка) намеренно **не** вынесены в MCP — остаются в
человеческом CLI-контуре с явным подтверждением.

## 5. Остаточные риски (честно)

| Риск | Статус | Митигация |
|---|---|---|
| `RLIMIT_AS` на fork внешних команд (bash) | 🟡 известен | shell-лимиты без `RLIMIT_AS` (задокументировано в skill) |
| Phase 3 (Falco/Tetragon) eBPF-агент | ⏳ не реализован | только enterprise on-prem >10 тенантов (Трек 0.6) |
| SOC 2 Type I/II | ⏳ | отложен до Enterprise-спроса |
