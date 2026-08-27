# GSC Roadmap

> v1.4.0 — актуальное состояние. Инженерная история версий — в git-логе.

## ✅ Shipped — v1.4.0

### Платформа
- **Детекция** — 47 детекторов (SAST · SCA · Secrets · IaC), YAML rule DSL, реестр правил.
- **LLM-триаж** — confidence scoring, cross-model voting, panel + judge, logprob-калибровка.
- **Reachability** — AST-анализ импортов (PyPI / npm / Go) + deploy-context (prod vs dev vs base-image).
- **GitHub** — App (Check Runs), webhook-автоскан, PR-комментарии, required status checks.

### Доказательство и исправление
- **PoC auto-generation** — рабочий эксплойт для каждой находки.
- **Proof-of-Fix** — патч верифицируется перезапуском эксплойта в изолированном sandbox.
- **Self-healing CI** — авто-PR с верифицированными фиксами.
- **Dependency-PoF** + adversarial re-attack (мутация payload).
- **DAST** — экспорт в nuclei, валидация на staging.

### Интеллект
- Security archaeology (полный lifespan уязвимости), predictive forecasting (heatmap).
- NL Policy (правила на естественном языке), exploit chains.
- Cross-repo secret correlation (только хеши), live-проверка секретов (GitHub / Slack / Stripe).
- SCA license compliance (SPDX), threat modeling (DREAD / PASTA / attack trees).
- STIX 2.1 / TAXII 2.1 экспорт (MISP / OpenCTI).
- Self-learning — adaptive thresholds, авто-деактивация шумных паттернов.

### Интеграции и Enterprise
- VSCode extension, MCP server.
- GitLab MR-адаптер, трекеры Jira / Linear / GitLab.
- Enterprise: RBAC, SSO/OIDC, audit, multi-tenancy, Helm, air-gap.
- SaaS API (multi-tenant), SBOM (CycloneDX / SPDX + VEX).

## 🟡 In progress

- LLM first-pass auditor — whole-repo semantic pass (модуль готов, идёт интеграция в оркестратор).
- Мультиязычные sandbox-раннеры (Node / Go / Java / Rust) — manifest-парсеры готовы.
- NL-policy через AST / Data Flow — семантические правила поверх regex.

## ⬜ Planned

- Локальные LLM (air-gap) и батч-ревалидация legacy-находок.
- Open-core split (community vs enterprise packages).
- PostgreSQL-хранилище (сейчас SQLite).
- SaaS S2–S3 — workers, очереди, биллинг.
- Observability — structlog / Prometheus / OTel.
