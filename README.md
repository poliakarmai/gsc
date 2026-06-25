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

# Инициализация в проекте (создаёт .gsc/ + GitHub Action)
cd my-project
python3 ~/gsc/gsc.py init

# Веб-дашборд
python3 gsc.py dashboard
# → http://localhost:8080
```

---

## 🗺️ Дорожная карта

| Фаза | Срок | Что | Статус |
|------|------|-----|--------|
| **1. Упаковка** | Июль 2026 | CLI + 223 паттерна + дашборд + `gsc init` | ✅ Готово |
| **2. Интеграция** | Август 2026 | GitHub Action + GitLab CI + SARIF экспорт | 🔜 |
| **3. Масштабирование** | Сентябрь 2026 | Поддержка Go, TypeScript, Rust + авто-фиксы | 📋 |
| **4. Монетизация** | Октябрь 2026 | SaaS (gsc.cloud) + тарифы Free/Pro/Team | 📋 |
| **5. Сеть** | Ноябрь 2026 | Федеративное обучение + паттерн-маркетплейс | 📋 |

### Фаза 1: Упаковка ✅

- [x] CLI: `gsc scan`, `gsc init`, `gsc dashboard`, `gsc patterns`, `gsc db`
- [x] 223 seed-паттерна (OWASP Top 10, CWE Top 25, Python-specific)
- [x] Веб-дашборд с историей, трендами и эффективностью паттернов
- [x] `gsc init` — авто-установка `.gsc/` + GitHub Actions CI-шаблон
- [x] Persistent SQLite DB + Obsidian-отчёты

### Фаза 2: Интеграция 🔜

- [ ] GitHub Action: `poliakarmai/gsc-action@v1` — аудит в каждом PR
- [ ] GitLab CI шаблон
- [ ] SARIF экспорт (совместимость с GitHub Code Scanning)
- [ ] `.gsc/config.yaml` — per-project ignore-листы и пороги
- [ ] Slack/Telegram нотификации при CRITICAL находках

### Фаза 3: Масштабирование 📋

- [ ] Поддержка Go, TypeScript, Rust, Java
- [ ] Инфра-конфиги: Terraform, Kubernetes, Docker
- [ ] Авто-фиксы: AI предлагает diff → click to apply
- [ ] Pre-commit hook: локальный аудит до коммита

### Фаза 4: Монетизация 📋

- [ ] SaaS: `gsc.cloud` — регистрация → подключить репо → аудит
- [ ] Тарифы: Free (1 public repo) / Pro ($29/мес) / Team ($99/мес)
- [ ] On-premise лицензия для enterprise
- [ ] Stripe/Paddle биллинг

### Фаза 5: Сеть 📋

- [ ] Федеративное обучение: паттерны из N проектов → общий пул
- [ ] Анонимизация: opt-in, GDPR-friendly
- [ ] Паттерн-маркетплейс: «PCI DSS паттерны от Security Corp — $99»

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
