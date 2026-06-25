# 🔒 GSC — Git Security Checker

> Самообучающаяся система аудита кода. Не просто находит баги — запоминает их и умнеет с каждым проектом.

[![Phase](https://img.shields.io/badge/phase-1%20(CLI)-blue)](https://github.com/poliakarmai/gsc)
[![Patterns](https://img.shields.io/badge/patterns-223-green)](https://github.com/poliakarmai/gsc)
[![Projects](https://img.shields.io/badge/projects%20audited-6-orange)](https://github.com/poliakarmai/gsc)

---

## 🤔 Проблема

Статические анализаторы (SonarQube, Snyk, Semgrep) работают по жёстким правилам. Они находят `SQL injection` по сигнатуре `f"SELECT {var}"`, но **никогда** не найдут:

- *«В этом проекте `round(..., 2)` в финансах — баг, нужно 6 знаков»*
- *«После рефакторинга промокодов сломалась схема БД — колонки `valid_from` стали `created_at`»*
- *«Вот этот конкретный паттерн TOCTOU уже 3 раза приводил к потере данных»*

Такие находки рождаются только из **опыта на конкретных проектах**. И они теряются сразу после аудита.

GSC их сохраняет.

---

## 🧠 Как это работает

```
┌─────────────────────────────────────────────────────┐
│                    GSC scan pci-index                │
├─────────────────────────────────────────────────────┤
│  Seed Patterns (223)                                 │
│  ├── OWASP Top 10: SQL injection, XSS, SSRF...      │
│  ├── CWE Top 25: buffer overflow, race conditions   │
│  └── Python: bare except, eval(), pickle...          │
│                                                      │
│  Learned Patterns (из прошлых аудитов)               │
│  ├── PCI: round() precision mismatch (2dp vs 6dp)   │
│  ├── VPN: promo_redeem SQL schema mismatch          │
│  ├── bybit-ws: state.db world-readable              │
│  └── Apolaibot: PUBLIC_URL literal in f-string      │
│                                                      │
│  3 Echelons:                                         │
│  ├── E1 Source-Driven: grep-паттерны, импорты       │
│  ├── E2 Security: права, ключи, systemd hardening   │
│  └── E3 Adversarial: race conditions, precision     │
│                                                      │
│  Результат: 62 находки → SQLite + Obsidian 📝       │
└─────────────────────────────────────────────────────┘
```

**Ключевая фича:** после каждого аудита находки сохраняются в базу. Следующий аудит (любого проекта) получает их как **дополнительные паттерны**. Чем больше проектов — тем умнее GSC.

---

## 📊 Самообучение в цифрах

| Метрика | Значение |
|---------|----------|
| Seed-паттернов (OWASP/CWE/Python) | 223 |
| Паттернов, рождённых из реальных находок | 62+ |
| Проектов отaudit'овано | 6 |
| Всего находок в базе | 100+ |
| Audit runs | 5 |

Каждый паттерн имеет `true_positive / false_positive` счётчик. При эффективности < 30% автоматически деактивируется — GSC сам чистит ложные срабатывания.

---

## 🚀 Быстрый старт

```bash
# Установка
git clone https://github.com/poliakarmai/gsc.git
cd gsc
pip install ripgrep  # единственная зависимость

# Первый аудит
python3 gsc.py scan my-project

# Интерактивный триаж (разметка TP/FP)
python3 gsc.py triage my-project

# Развёрнутое объяснение находки
python3 gsc.py explain 42

# Pre-commit hook (блокирует CRITICAL findings)
cp pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Веб-дашборд
python3 gsc.py dashboard
# → http://localhost:8080
```

---

## 🗺️ Дорожная карта

| Фаза | Срок | Что | Статус |
|------|------|-----|--------|
| **1. Упаковка** | Июль 2026 | CLI + 277 паттернов + дашборд + triage | ✅ |
| **2. Интеграция** | Август 2026 | GitHub Action + pre-commit + baseline + diff-only | 🔜 |
| **2.5. IDE** | Сентябрь 2026 | VSCode extension + explain + Jira/Linear | 📋 |
| **3. Масштабирование** | Октябрь 2026 | 7 языков + авто-фиксы + SBOM | 📋 |
| **3.5. Enterprise** | Ноябрь 2026 | SSO + RBAC + Helm chart | 📋 |
| **4. AI-remediation** | Декабрь 2026 | Auto-fix v2 + тесты + контекстные патчи | 📋 |
| **5. Сеть** | Январь 2027 | Федеративное обучение + паттерн-маркетплейс | 📋 |
| **6. Compliance** | Февраль 2027 | PCI DSS + SOC2 auto-reports + evidence collection | 📋 |

### Фаза 1: Упаковка ✅

- [x] CLI: `gsc scan`, `gsc init`, `gsc dashboard`, `gsc triage`, `gsc explain`, `gsc fix`, `gsc patterns`, `gsc db`
- [x] 277 seed-паттернов (OWASP + CWE + 7 языков: Python/Go/TS/Rust/Java/Docker/Terraform)
- [x] Веб-дашборд с историей, трендами и эффективностью паттернов
- [x] `gsc triage` — интерактивная разметка TP/FP (основа самообучения)
- [x] `gsc explain` — CVSS-оценка, threat/impact для каждой находки
- [x] Pre-commit hook — блокирует коммиты с CRITICAL находками
- [x] GitHub Action: `poliakarmai/gsc-action@v1`
- [x] Persistent SQLite DB + Obsidian-отчёты

### Фаза 2: Интеграция + DX 🔜

- [ ] Baseline/suppressions — чтобы CI не спамил старыми находками
- [ ] Diff-only scan — аудит только изменённых строк в PR
- [ ] SARIF экспорт (совместимость с GitHub Code Scanning)
- [ ] Шифрование БД (SQLCipher) — до первых внешних пользователей
- [ ] Corpus-тесты для паттернов — без них контрибьюции невозможны

### Фаза 2.5: IDE & Developer Experience 📋

- [ ] VSCode extension: подсветка находок прямо в редакторе
- [ ] Jira/Linear integration: находка → тикет одним кликом
- [ ] HTML/PDF экспорт для тех, кто не в Obsidian
- [ ] `gsc fix <id>` — AI-патч (MVP: inline, полный: Hermes delegate_task)

### Фаза 3: Масштабирование 📋

- [ ] 7 языков: Python, Go, TypeScript, Rust, Java, Docker, Terraform (seed-паттерны уже есть)
- [ ] SBOM-генерация (CycloneDX) — supply chain security
- [ ] Typosquatting detection в зависимостях
- [ ] Compliance mapping: finding → PCI DSS / SOC2 / ISO27001
- [ ] Performance: <10 сек на 10K LOC

### Фаза 3.5: Enterprise 📋

- [ ] SSO (SAML/OIDC) для команд
- [ ] RBAC: admin / auditor / viewer
- [ ] Audit log: кто, когда, какой finding подтвердил
- [ ] On-premise Helm chart для Kubernetes
- [ ] Multi-tenancy с изоляцией данных

### Фаза 4: AI-ремедиация 📋

- [ ] Auto-fix v2: не просто diff, а полный PR с тестами
- [ ] Context-aware suggestions: учитывает стиль кода проекта
- [ ] Regression test generation: AI пишет тест, доказывающий фикс

### Фаза 6: Compliance-as-a-Service 📋

- [ ] Автоматическая генерация audit-отчётов для PCI DSS / SOC2
- [ ] Continuous compliance monitoring — не разовый скан, а постоянный
- [ ] Evidence collection для аудиторов (скриншоты, логи, git history)

### Фаза 7: Экосистема 📋

- [ ] Pattern marketplace с рейтингами
- [ ] Community rules hub (а-ля ESLint shareable configs)
- [ ] Bug bounty integration: finding → отчёт в HackerOne
- [ ] GSC Academy: сертификация «GSC Auditor»

---

## 📊 Метрики самообучения

| Метрика | Значение | Зачем |
|---------|----------|-------|
| Всего паттернов | 277 | Seed + learned |
| Паттернов из реальных находок | 62+ | Самообучение в действии |
| TP/FP на паттерн | per-pattern counter | Авто-деактивация < 30% |
| Проектов отaudit'овано | 6 | Разнообразие кодовых баз |
| Audit runs | 5 | История для трендов |
| Precision | TP/(TP+FP) | Качество каждого паттерна |
| Cross-project transfer | tracked | Как часто паттерн срабатывает в новых проектах |

> **Живой счётчик:** GSC нашёл **100+** уязвимостей в **6** проектах. Следующий скан будет умнее.

---

## 🆚 Почему не SonarQube/Snyk/Semgrep?

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| 3 эшелона (Source+Security+Logic) | ✅ | ❌ | ❌ | ❌ |
| Самообучение на реальных находках | ✅ | ❌ | ❌ | ❌ |
| LLM-рассуждение (не regex) | ✅ | ❌ | ❌ | ❌ |
| False-positive auto-cleanup | ✅ | ❌ | ❌ | ❌ |
| Чейнинг (fix→pattern→next audit) | ✅ | ❌ | ❌ | ❌ |
| Человекочитаемые Obsidian-отчёты | ✅ | ❌ | ❌ | ❌ |
| Автономный (не требует сервера) | ✅ | ❌ | ❌ | ✅ |
| Open source | ✅ | ❌ | ❌ | ✅ |

---

## 🏗️ Архитектура

```
~/.hermes/state/gsc_audit.db    ← SQLite (SSOT)
    ├── patterns (223+)
    ├── findings (100+)
    └── audit_runs (5)

~/gsc/
    ├── gsc.py                   ← CLI
    ├── patterns/*.json          ← Seed-паттерны
    └── dashboard/               ← Веб-интерфейс

~/obsidian-vault/audits/        ← Человеческие отчёты
    ├── gsc-patterns.md
    ├── gsc-YYYY-MM-DD.md
    └── findings/*.md
```

---

## 🤝 Контрибьюция

GSC на стадии MVP. Нужны:

- **Python-разработчики:** новые паттерны, интеграции с языками
- **Security-инженеры:** OWASP/CWE/NIST-покрытие
- **DevOps:** GitHub/GitLab CI, Docker-образ
- **Дизайнеры:** дашборд, лендинг gsc.cloud

Issues и PR: [github.com/poliakarmai/gsc](https://github.com/poliakarmai/gsc)

---

*GSC — потому что твой линтер не помнит, что случилось вчера.*
