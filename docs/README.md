# 📚 GSC Documentation

> Навигация по документации GSC (Git Security Checker). Актуальные числа — `python3 gsc_meta.py` (SSOT).
> Главный вход для пользователя — [README.md](../README.md). Для AI-агентов — [AGENTS.md](../AGENTS.md) и [PROJECT.md](../PROJECT.md).

## 🚀 Быстрый старт

| Документ | Что внутри |
|---|---|
| [INSTALL.md](INSTALL.md) | Установка и зависимости |
| [USAGE.md](USAGE.md) | Основные сценарии использования |
| [CONFIG.md](CONFIG.md) | Конфигурация и профили |
| [PATTERNS.md](PATTERNS.md) | Языковые пакеты детекторов (seed patterns) |
| [TESTING.md](TESTING.md) | Как запускать и писать тесты |

## 🏗️ Архитектура

| Документ | Что внутри |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Высокоуровневая архитектура платформы |
| [PACKAGES_SPLIT_PLAN.md](PACKAGES_SPLIT_PLAN.md) | Разбиение на `gsc_core` / `gsc_cli` / `gsc_cloud` (0.5.x) |
| [SCHEMA_CONTRACT.md](SCHEMA_CONTRACT.md) | Контракт схемы БД (schema 33) |
| [CRITICAL_PATH.md](CRITICAL_PATH.md) | Критический путь пайплайна |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Модель угроз (изоляция PoC, границы) |
| [adr/](adr/) | Architecture Decision Records |

## 🥇 Эксклюзивные фичи

| Документ | Что внутри |
|---|---|
| [GSC_PROOF_OF_FIX_ARCHITECTURE_EN.md](GSC_PROOF_OF_FIX_ARCHITECTURE_EN.md) | Proof-of-Fix — архитектура (EN) |
| [GSC_PROOF_OF_FIX_ARCHITECTURE_RU.md](GSC_PROOF_OF_FIX_ARCHITECTURE_RU.md) | Proof-of-Fix — архитектура (RU) |
| [POF_CORPUS_TASK.md](POF_CORPUS_TASK.md) | Корпус задач Proof-of-Fix |
| [MCP_SERVER.md](MCP_SERVER.md) | MCP-сервер (GSC как инструмент для AI-агентов) |
| [EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md](EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md) | Экспертиза: IAST runtime-валидатор |
| [EXPERTISE_02_FEDERATED_PRIVACY.md](EXPERTISE_02_FEDERATED_PRIVACY.md) | Экспертиза: federated privacy (DP) |

## 🔍 Детекторы

- **38 brief'ов** на детекторы GS000–GS039: `DETECTOR_BRIEF_GS###.md`
- [DETECTOR_TRAINING_STATUS.md](DETECTOR_TRAINING_STATUS.md) — статус обучения/покрытия детекторов
- [DETECTOR_IMPROVEMENT_BRIEF.md](DETECTOR_IMPROVEMENT_BRIEF.md) — план улучшения детекторов

## 🚀 Деплой и Ops

| Документ | Что внутри |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Развёртывание |
| [SOC2_CONTROLS.md](SOC2_CONTROLS.md) | SOC2-контроли |
| [compliance.md](compliance.md) | Комплаенс-маппинг (CWE/OWASP/PCI) |
| [DUE_DILIGENCE_v2.md](DUE_DILIGENCE_v2.md) | Due-diligence-контракт |
| [LEGAL_AUDIT.md](LEGAL_AUDIT.md) | Юридический аудит |
| [LICENSE_AUDIT.md](LICENSE_AUDIT.md) | Аудит лицензий зависимостей (нет GPL) |
| [AUTHORSHIP.md](AUTHORSHIP.md) | Доказательства авторства (chain-of-title) |
| [DPA_template.md](DPA_template.md) | DPA-шаблон |

## 🏢 Enterprise / SaaS

| Документ | Что внутри |
|---|---|
| [ENTERPRISE_AGENT.md](ENTERPRISE_AGENT.md) | Enterprise-агент |
| [ENTERPRISE_HARDENING.md](ENTERPRISE_HARDENING.md) | Hardening (RBAC, SSO, multi-tenancy) |
| [SAAS_STRATEGY.md](SAAS_STRATEGY.md) | SaaS-стратегия |
| [S1_IMPLEMENTATION.md](S1_IMPLEMENTATION.md) | SaaS Stage 1 — multi-tenant API |
| [S2_IMPLEMENTATION.md](S2_IMPLEMENTATION.md) | SaaS Stage 2 — воркеры/очереди |
| [S3_IMPLEMENTATION.md](S3_IMPLEMENTATION.md) | SaaS Stage 3 — биллинг |
| [S4_IMPLEMENTATION.md](S4_IMPLEMENTATION.md) | SaaS Stage 4 — OIDC/SSO |
| [GSC-CLOUD-V2-OIDC-CANARY.md](GSC-CLOUD-V2-OIDC-CANARY.md) | OIDC canary (cloud v2) |

## 🗺️ Roadmap и планы

| Документ | Что внутри |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Дорожная карта |
| [ROADMAP_MATURITY.md](ROADMAP_MATURITY.md) | Зрелость дорожной карты |

## 📣 Маркетинг, награды, метрики

| Документ | Что внутри |
|---|---|
| [one-pager.md](one-pager.md) | One-pager для продажи |
| [GSC_DETECTOR_PRECISION_BRIEF.md](GSC_DETECTOR_PRECISION_BRIEF.md) | Precision-отчёт детекторов |
| [IT_ELEMENTS_AWARD_2026.md](IT_ELEMENTS_AWARD_2026.md) | Заявка IT Elements 2026 |
| [SECURITY_AWARDS.md](SECURITY_AWARDS.md) | Награды по безопасности |
| [GSC_PROOF_OF_FIX_HABR.md](GSC_PROOF_OF_FIX_HABR.md) | Статья Proof-of-Fix (Habr) |
| [GSC_PROOF_OF_FIX_TG.md](GSC_PROOF_OF_FIX_TG.md) | Пост Proof-of-Fix (Telegram) |

## ⚠️ Ограничения и статус

| Документ | Что внутри |
|---|---|
| [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) | Честные границы продукта |
| [AUTONOMOUS_WORK_REPORT.md](AUTONOMOUS_WORK_REPORT.md) | Отчёт автономной работы |
| [SECURITY_FIX_REPORT.md](SECURITY_FIX_REPORT.md) | Отчёт по security-фиксам |
| [PILOT_GUIDE.md](PILOT_GUIDE.md) | Гайд по пилотам |
| [BOUNTY_COLLECTOR.md](BOUNTY_COLLECTOR.md) | Bug-bounty collector |

## 📄 Прочее

- [openapi.json](openapi.json) — OpenAPI-спецификация REST API
- [archive/](archive/) — архив устаревших документов
