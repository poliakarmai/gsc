# GSC Roadmap

> v1.4.0 — актуальное состояние (обновлено 2026-08-28). Инженерная история версий — в git-логе.

## ✅ Shipped — v1.4.0

### Платформа
- **Детекция** — 50 детекторов (46 registry + 4 движка: SAST · SCA · Secrets · IaC), YAML rule DSL, реестр правил.
- **LLM-триаж** — confidence scoring, cross-model voting, panel + judge, logprob-калибровка.
- **Reachability** — AST-анализ импортов (PyPI / npm / Go) + deploy-context (prod vs dev vs base-image).
- **GitHub** — App (Check Runs), webhook-автоскан, PR-комментарии, required status checks.
- **Air-gap LLM** — локальные провайдеры Ollama / LM Studio без внешнего API-ключа + failover-цепочка.

### Доказательство и исправление
- **PoC auto-generation** — рабочий эксплойт для каждой находки.
- **Proof-of-Fix** — патч верифицируется перезапуском эксплойта в изолированном sandbox.
- **Self-healing CI** — авто-PR с верифицированными фиксами.
- **Dependency-PoF** + adversarial re-attack (мутация payload).
- **DAST** — экспорт в nuclei, валидация на staging.
- **Мультиязычные sandbox-раннеры** — Proof-of-Fix для Node / Go / Java / Rust (Node + Java live, Go/Rust генераторы готовы).

### Recon (bug bounty)
- **Passive reconnaissance** — `gsc_recon/`: subdomain enumeration (crt.sh), tech detection (36 сигнатур), raw-DNS (RFC 1035), HTTP probing; оркестратор `subdomains → dns → http → tech`.
- **Параллелизация** — resolve/dns/http стадии конкурентно (ThreadPoolExecutor), детерминизм по исходному порядку.

### Верификация и приоритизация
- **FP-фильтры** — CSP-aware XSS, CDN-aware directory listing.
- **БДУ ФСТЭК** — каталог уязвимостей (`gsc_bdu.py`), нормализация `BDU:YYYY-NNNNN`.
- **EPSS + CISA KEV + ExploitDB** — приоритизация по вероятности эксплуатации, а не по сырому CVSS.
- **VERIFICATION_RULES.md** — правила верификации (PoC прогоняется в sandbox, «находку проверяет не тот агент»).
- **Новые детекторы** — File Upload (`YAML-UPLOAD001`), NetScaler misconfig (`YAML-NETSCALER001`).

### Интеллект
- Security archaeology (полный lifespan уязвимости), predictive forecasting (heatmap).
- **LLM first-pass auditor** — whole-repo semantic pass (`gsc first-pass [repo]`): walk → select_relevant_files → prompt → LLM → parse (hallucinated paths dropped).
- NL Policy (правила на естественном языке), exploit chains.
- **NL-policy через AST/Data Flow** — семантические taint-правила (source → flow → sink) поверх regex.
- **Батч-ревалидация legacy-находок** — multi-model panel + judge, авто-триаж.
- Cross-repo secret correlation (только хеши), live-проверка секретов (GitHub / Slack / Stripe).
- SCA license compliance (SPDX), threat modeling (DREAD / PASTA / attack trees).
- STIX 2.1 / TAXII 2.1 экспорт (MISP / OpenCTI).
- Self-learning — adaptive thresholds, авто-деактивация шумных паттернов.

### Интеграции и Enterprise
- VSCode extension, MCP server.
- GitLab MR-адаптер, трекеры Jira / Linear / GitLab.
- Enterprise: RBAC, SSO/OIDC, audit, multi-tenancy, Helm, air-gap.
- SaaS API (multi-tenant), SBOM (CycloneDX / SPDX + VEX).

## ⬜ Planned

- **Open-core split** (community vs enterprise packages).
- **PostgreSQL-хранилище** — сейчас SQLite; `gsc_cloud/gsc_db_backend.py` есть, но не в проде.
- **Observability** — structlog + Prometheus `/metrics` (`gsc_cloud/observability.py`, v1.4.0) готовы; OTel (tracing) не начат.
- **SaaS S4** — SOC 2 Type I, DPA (S1–S3 реализованы в `gsc_cloud/`, см. `GSC_SAAS_ROADMAP.md`).
- **LLM-first позиции bug bounty** — OAuth, Account Takeover, Rate Limiting (семантические, не regex).
- **vLLM-провайдер** — air-gap: Ollama и LM Studio есть, vLLM не добавлен.
