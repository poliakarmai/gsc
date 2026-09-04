# 🧠 Self-Learning Detector Engine

> **Первый SAST, где детекторы уязвимостей обновляются сами — каждую ночь, без LLM,
> без ручного ревью правил, без раскрытия кода клиента.**

## Суть

GSC замыкает петлю обучения, которую никто из мейнстрим-вендоров не замыкает:

```
скан репо
  → Ground-Truth Trainer: авто-разметка findings по calibration-сети
    (16 проектов: 9 clean + 7 vuln = эталон TP/FP, без LLM)
  → авто-деактивация шумных паттернов (<30% TP при ≥10 вердиктах)
  → пополнение эталонов из security-фидов (crypto watchlist → bounty_examples)
  → federated submit/fetch (privacy-first, DP-noised: только {tenant_hash, rule_id, tp, fp})
```

**Ключевые свойства:**
- **0 LLM** — разметка детерминированная по calibration-сети, не галлюцинирует.
- **Откат тривиален** — дискретные деактивации паттернов, след в БД, без переписывания весов.
- **Federated** — детекторы учатся на сигналах всех тенантов без раскрытия их кода.
- **Ежедневно** — не «раз в квартал с релизом».

## Почему это уникально — конкуренты (пруф)

| Вендор | Как обновляет правила | Self-learning / Federated | Пруф |
|---|---|---|---|
| **Semgrep** | Вручную, коммиты в публичное репо правил | ❌ нет | github.com/semgrep/semgrep-rules |
| **GitHub CodeQL** | Вручную (GitHub Security Lab) + комьюнити + бот-апдейты | ❌ нет | github.com/github/codeql |
| **Snyk Code (DeepCode)** | Офлайн-ML на OSS, релизы версиями | ❌ **явно «never customer data»** — исключает online-обучение | snyk.io/platform/deepcode-ai/ |
| **SonarQube** | Вручную командой SonarSource, релизы с анализаторами | ❌ нет | docs.sonarsource.com/.../rules/ |
| **Checkmarx** | Вручную (research team), пруфов ML/self-learning нет | ❌ нет | checkmarx.com/product/cxsast/ |

**Вывод:** мейнстрим = либо **человеческие правила** (Semgrep/CodeQL/SonarQube), либо
**офлайн-ML** (Snyk DeepCode, замороженная до релиза). Snyk прямо пишет «never customer
data» — то есть **сознательно отказывается** от обучения на живых находках клиентов,
которое GSC делает через federated-контур.

## Research-пруф: «self-learning SAST» — это прототипы, не продукты

По federated/continuous self-learning для SAST найдены только arxiv-препринты и
академические прототипы — ни одной production-системы:

| Работа | Год | Что делает | URL |
|---|---|---|---|
| Federated Learning for Vulnerability Detection (эмпирика) | 2024 | Сравнивает FL vs централизованное обучение | arxiv.org/abs/2411.16099 |
| Keeping Pace with Ever-Increasing Data (continual code intelligence) | 2023 | Continual learning моделей кода — **offline** | arxiv.org/abs/2302.03482 |
| Frequency-Aware Continual Learning (smart-contract vuln) | 2026 | Continual learning LLM-детектора — **offline** | arxiv.org/abs/2608.19680 |
| MoCQ (neuro-symbolic, LLM-генерация паттернов для SAST) | 2025 | LLM генерит правила — разово | arxiv.org/abs/2504.16057 |
| QRS (автосинтез Semgrep/CodeQL/SonarQube правил) | 2026 | LLM синтезирует правила — разово | arxiv.org/abs/2602.09774 |
| RuleLLM (YARA-правила для malware-пакетов) | 2025 | LLM → правила — разово | arxiv.org/abs/2504.17198 |
| DeepCode AI Fix (Snyk) | 2024 | LLM **фиксит** уязвимости, но НЕ online-retrain детектора | arxiv.org/abs/2402.13291 |
| QASecClaw (multi-agent FP-reduction в SAST) | 2026 | LLM-триаж FP — offline, не обучение | arxiv.org/abs/2605.01885 |

**Ключевой зазор:** академия показывает *continual/federated learning* как
исследовательскую идею, вендоры — как офлайн-ML или ручные правила. **Closed-loop
online self-learning детекторов в проде — не делает никто.** GSC закрывает ровно этот зазор.

## Почему конкуренты так не делают (и почему у GSC получается)

Мейнстрим боится **катастрофического дрейфа**: онлайн-обучение на живых находках без
ручного ревью рискует за день развалить качество (FP-каскад, забывание паттернов,
отравление фида). Поэтому они жертвуют скоростью ради стабильности: офлайн + релиз + ревью.

GSC обходит это **консервативным self-learning, а не нейрообучением**:
- разметка findings по **фиксированной calibration-сети** (не переписывание весов);
- **дискретные** деактивации/промоушены паттернов (не градиенты);
- каждый шаг **детерминированный**, след в SQLite, откат тривиален;
- federated только агрегатами `{tenant_hash, rule_id, tp, fp}` + DP-шум (приватно).

Итог: скорость ежедневного апдейта + отсутствие обратной стороны нейрообучения.

## Позиционирование

**«Первый self-learning SAST с federated-контуром: детекторы учатся на реальных
находках каждую ночь — без LLM, без дрейфа, без раскрытия кода клиента.»**

- Semgrep/CodeQL = ручные правила;
- Snyk = офлайн-ML «никогда на твоих данных»;
- **GSC = единственный, кто замыкает петлю обучения в проде.**

---
*Источник: веб-исследование 03.09.2026 — доки вендоров + arxiv API (25 работ).*
*Ограничение: Google Scholar/IEEE/USENIX не покрыты (IP-блок), охват академии — arxiv.*
