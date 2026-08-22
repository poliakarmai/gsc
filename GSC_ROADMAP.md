# GSC Roadmap

> **v1.4.0** · 47 детекторов (43 registry + 4 engines) · schema 33 · 165 модулей · 610 тестов
> **Приоритет №1: Precision** — снижение FP до уровня, пригодного для пилотов (Фаза 8).

---

## Фазы

### Фаза 1 — Packages split ✅
Физическое разделение монолита на `gsc_core` / `gsc_cli` / `gsc_cloud` с shim-совместимостью.

- ✅ 0.5.1 движок + детекторы → `gsc_core/`
- ✅ 0.5.2 CLI + сканеры → `gsc_cli/`
- ✅ 0.5.3 SaaS → `gsc_cloud/`
- ✅ 0.5.4 collector + тесты
- ✅ 0.5.5 shim + cleanup (272+ тестов зелёные)

### Фаза 2 — Runtime Validator (IAST) 🟡
Proof-of-Fix верификация по факту runtime-эксплуатации, а не по stdout-маркеру.

- ✅ Phase 1 — in-process monkeypatch (`open`/`subprocess`/`socket`) → JSONL
- ✅ Phase 2 — strace-валидация (`openat`/`connect`/`execve`)
- ⏳ Phase 3 — Falco/Tetragon-агент (enterprise on-prem, >10 тенантов) — отложено

### Фаза 3 — Sale-Readiness 🟡
Готовность к due-diligence покупателя.

- ✅ pytest collectible, README evidence-backed, MCP server (read-only)
- ⏳ design partners + paid pilots (бизнес)
- ⏳ IP: waivers, chain-of-title (юр.)
- ❌ benchmark vs Semgrep/CodeQL/Bandit
- ❌ enterprise hardening (sandbox threat model, egress, LLM retention)

### Фаза 4 — GSC Bot 📝
GitHub App для виральной верификации чужих PR (`@gsc scan` → badge + check-run). Спроектирован (`docs/GSC_BOT.md`), ~2 недели.

### Фаза 5 — Языки JS/TS/Go 📝
Снять потолок роста (сейчас Python-first, на Java/JS/Go 0–слабый TPR). Фокус top-5 детекторов, ~2–3 недели.

### Фаза 6 — Security Debt Ledger 📝
Перевод тех. риска в деньги: severity + EPSS → annualized loss. Язык бюджета для CISO. ~1–2 недели.

### Фаза 7 — Agentic Self-Healing 📝
patch → test → retry до success (поверх существующего `gsc_selfhealing.py`). ~2 недели.

### Фаза 8 — Precision 🔄 (приоритет №1)
Снижение FP. Цель: precision CRIT ≥50%, HIGH ≥40% до старта пилотов.

- ✅ GS008 (голый eval) + data-quality (395K rule_id) + CVE→inactive + голые chmod/Rust-unsafe деактивированы
- ✅ перезамер 100 проектов (22.08): CRIT 4302 → **1309**, recall 10/10, precision CRIT ~15% (было ~4–5%)
- 🔄 следующий: GS001 (613 CRIT = 47%) — secrets-экстрактор, главный FP-кластер (django 343, next.js 165, ruff 111)

### Фаза 9 — Traction / GTM ⚠️
4★, 0 форков → 100+.

- ICP-фокус: mid-size SaaS с активным CI/CD
- Ниша: security для LLM-generated code (GS025 AI-provenance — козырь)
- Free/paid граница явно задокументирована

### Фаза 10 — DD-аудит ✅
Supply-chain immutability + воспроизводимый benchmark как доказательная база.

- ✅ 0.14.1 sandbox escape CI (Docker + fail-closed gate)
- ✅ 0.14.2 benchmark 100 проектов (pinned revisions)
- ✅ 0.14.3 SBOM + provenance
- ✅ 0.14.4 свои образы digest-pin
- ✅ 0.14.5 AutoFix draft-only

---

## Сквозные направления

### Юридический фундамент 🟡
BSL → Apache 2.0 + Commercial ✅, SPDX ✅, CLA ✅, gitleaks ✅, аудит лицензий ✅, доказательства авторства ✅. **Trademark ⏳** (1 нед).

### SaaS Cloud (S1–S4) 📝
Спроектирован (~16–20 нед): S1 PostgreSQL+RLS → S2 GitHub App → S3 Dashboard+Stripe → S4 SOC2+Marketplace. До S1 позиционируется как single-tenant/self-hosted.

### Enterprise hybrid agent 📝
Runner + activation + air-gap. 2–3 недели (после S1).

### VSCode extension ✅
Open VSX опубликован. GitHub Releases (VSCode Marketplace недоступен из РФ).

### Бизнес / продажи 🔜
one-pager → пилоты (после S2) → платежи (после S3).

---

## Что уже готово (сжато)

- **Ядро v0.11 → v1.4.0:** PoC Auto-Generation, Exploit Chain Composer, Temporal Mutation Tracker, Invariant Engine, calibration 13/13, self-learning, MTTFV SLA, attack-graph, fix-quality, PoC watermarking, pre-commit.
- **Web3/Crypto:** GS041–GS044 + web3 SCA (Solidity SAST, crypto-secrets, honeypot, trading-bots).
- **Безопасность:** внутренний аудит 28/28 + AppSec DD-01..10 ✅, pre-фильтр файлов ✅.
- **Инфраструктура:** Docker Compose, k8s-манифесты, FastAPI-роутеры, SQL-схемы, dashboard scaffold.

---

## Рекомендуемый план

| Период | Фокус | Результат |
|---|---|---|
| Авг–Сен 2026 | Фаза 8 (Precision) + S1/S2 + VSCode | GitHub App, 3–5 пилотов |
| Окт–Дек 2026 | S3 + первые платежи | Private beta Cloud |
| Янв–Мар 2027 | S4 + Enterprise agent | Cloud 1.0 GA |
| Апр–Июн 2027 | Marketplace-листинги, рост | Traction → решение |

**Критический путь:** Precision (Фаза 8) → S1 → S2 → пилоты → S3 → платежи ≈ 3 месяца до первых денег.

---

## Риски

| Риск | Митигация |
|---|---|
| Соло-пропускная способность | Жёсткая последовательность фаз |
| Precision CRIT ~5–10% | Фаза 8 в работе (GS008/GS000-LEGACY закрываются) |
| GHAS (CodeQL бесплатен для public) | Ниша AI-code + verified remediation, не «бесплатный SAST» |
| Конкуренты (Semgrep/Snyk) | Ниша self-learning + PoC, PLG free-tier |
| LLM-расходы при росте | Глобальный кэш по fingerprint, regex-first |
| Стоимость SOC 2 | Отложить до Enterprise-спроса |
