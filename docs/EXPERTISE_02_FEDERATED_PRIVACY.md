# Экспертиза #2 — Federated Learning Privacy Audit

> **Статус:** финализирован — решения §9 приняты 13.08.2026.
> **План реализации:** Шаг 1 TLS+HMAC (0.5д) → Шаг 2 ротация hash + RDP (3–5д) → Шаг 3 Shamir (enterprise).
> **Дата:** 13.08.2026
> **Автор:** Море (AI-агент) + Алексей Поляков
> **Связано:** `gsc_federated.py`, инвариант #5 («privacy-first federated»), GDPR/CCPA.

---

## 1. Проблема

Federated Self-Learning отправляет на центральный сервер метрики детекторов от каждого
тенанта. Заявлен инвариант (AGENTS.md #5):

> Privacy-first federated: только `{tenant_hash, rule_id, tp, fp}` + DP.

Вопрос экспертизы: **достаточно ли этого для заявленного «privacy-first»?** Можно ли
деанонимизировать тенанта или восстановить данные по его метрикам?

### 1.5. Бизнес-контекст

**Почему это важно:**
- «Privacy-first federated» — маркетинговое обещание (эксклюзив в линейке).
- GDPR/CCPA compliance требуется для enterprise-клиентов в EU/California.
- Если privacy-аудит покажет дыры → репутационный риск + юридический.

**Почему это НЕ блокирует первую продажу:**
- Federated Learning — опциональная фича, не ядро продукта.
- Первый пилот может работать на локальном self-learning (без федерации).
- Enterprise-клиенты могут отключить federated до privacy-аудита.

**Позиция:** privacy-аудит нужен **до** enterprise-продаж, но не блокирует первый пилот.

---

## 2. Текущая реализация (факты из кода `gsc_federated.py`)

| Аспект | Что в коде | Строка |
|--------|-----------|--------|
| Payload | `{tenant_hash, metrics: {rule_id: {tp, fp}}}` | 96 |
| `tenant_hash` | `sha256(f"gsc-tenant:{tenant_id}")[:16]`, `tenant_id` из `db.tenant_id` (default `"local"`) | 74–76 |
| DP-шум | `add_laplace_noise(count, epsilon=1.0)`, sensitivity=1, scale=1/ε | 29–36 |
| ε default | `1.0` | 71 |
| Шум применяется | только если `epsilon > 0` | 92 |
| Агрегация | по `base rule_id` (суффикс `-...` отрезается) | 23–25, 53 |
| Передача | `http POST /api/v1/federated/submit`, без подписи payload | 100–104 |

---

## 3. Замечания (подтверждённые кодом) + рекомендации

### 3.1. `tenant_hash` — псевдоним, НЕ анонимизация (linkability)
`sha256(f"gsc-tenant:{tenant_id}")` — **детерминированный**. Один и тот же тенант всегда
отправляет один hash → сервер связывает все submit'ы во времени; при предсказуемом
`tenant_id` (напр. `"local"`) — перебирает/угадывает hash. Для GDPR псевдоним = персональные
данные (Art. 4(5)).

**Рекомендация:** ротация `tenant_hash` по эпохам (7 дней).

```python
import hashlib, time

def _tenant_hash(tenant_id: str, rotation_period_days: int = 7) -> str:
    epoch = int(time.time()) // (rotation_period_days * 86400)
    return hashlib.sha256(f"gsc-tenant:{tenant_id}:{epoch}".encode()).hexdigest()[:16]
```

**Tradeoff:** ✅ unlinkability старше 7 дней; ❌ теряется долгосрочная история (self-learning
работает на скользящем окне — приемлемо). Альтернатива: случайный hash на каждый submit
(максимальная unlinkability, теряется вся история).

### 3.2. Нет privacy-budget accounting (composition)
Laplace ε=1.0 на каждый submit, ежедневный cron → эффективный ε растёт линейно (ε_eff ≈ N·ε).
После ~30 дней ε_eff ≈ 30 (катастрофически). Формальной ε-гарантии нет.

**Рекомендация:** перейти на Rényi DP (RDP) с composition-теоремой + budget accountant.

```python
from diffprivlib.mechanisms import Laplace
from diffprivlib.accountant import BudgetAccountant

accountant = BudgetAccountant()          # composition across submits
mechanism = Laplace(epsilon=1.0, sensitivity=1, accountant=accountant)

noisy = mechanism.randomise(count)       # прибавляет шум и тратит budget
epsilon_spent, _ = accountant.total()    # (ε_spent, δ_spent)

if epsilon_spent > 10.0:                 # порог: бюджет исчерпан
    disable_federated_for_this_tenant()
```

**Порог:** ε_spent > 10.0 → остановить federated для этого тенанта (budget exhausted).

### 3.3. Нет secure aggregation
Сервер видит per-tenant (зашумлённые) значения до агрегации. Модель honest-but-curious
не защищена: DP-шум на клиенте ≠ приватность «только агрегата».

**Рекомендация:** Shamir Secret Sharing (t-of-n) для secure aggregation.

1. Каждый тенант разбивает `tp`/`fp` на N shares (t = N/2 + 1).
2. Shares расходятся на N серверов (или peer-to-peer между тенантами).
3. Серверы агрегируют shares, видя **только сумму**, не индивидуальные значения.

**Tradeoff:** ✅ сервер видит только агрегат; ❌ требует N серверов / p2p, усложняет инфраструктуру.
**Позиция:** отложить до enterprise-фазы (>10 тенантов). Для MVP достаточно ротации hash + RDP accounting.

### 3.4. Нет MITM-защиты payload
Без TLS/pinning MITM видит `tenant_hash`+метрики и может инжектить/подменять веса
(отравление глобальной модели).

**Рекомендация:** TLS + HMAC-подпись payload — внедрить немедленно (0.5 дня).

### 3.5. ε=1.0 на малых счётчиках
Для rules с tp+fp < 10 шум ±1/ε «съедает» сигнал либо слабо защищает при повторе.
Покрывается RDP-accounting (§3.2) + порог `min_verdicts`.

---

## 4. Модель угрозы

| Атакующий | Что может | Текущий статус |
|-----------|-----------|----------------|
| Центральный сервер (honest-but-curious) | per-tenant метрики, linkability по hash | ❌ не защищено |
| Другой тенант | inference-атака на глобальные веса | ⚠️ частично (только агрегат) |
| MITM | перехват/подмена payload, отравление весов | ❌ без TLS/подписи |
| Внешний наблюдатель трафика | корреляция времени/размера | ⚠️ не анализировалось |

---

## 5. Альтернативы

| # | Подход | Что даёт | Стоимость |
|---|--------|---------|-----------|
| A | Текущий (Laplace ε=1.0, детерм. hash) | baseline | 0 |
| B | RDP + budget accounting + ротация hash | формальная ε-гарантия, unlinkability | 3–5 дн. |
| C | Secure aggregation (Shamir / DP-FedAvg) | сервер видит только агрегат | 1–2 нед., сервер+клиент |
| D | Local DP + clipping + бюджетирование | усиление приватности без сервера | 2–4 дн. |
| E | Только локальное self-learning (без федерации) | нет утечки вообще | фича-редукция |

---

## 6. Критерии приёмки (draft)

- [ ] Формальная DP-гарантия с ε ≤ 1.0 **и** budget accounting по composition.
- [ ] `tenant_hash` не связывается между submit'ами (ротация/случайный).
- [ ] Secure aggregation ИЛИ обоснование, почему per-tenant раскрытие приемлемо.
- [ ] TLS + HMAC-подпись payload против MITM/отравления весов.
- [ ] Документация compliance: GDPR Art. 25 (privacy by design), CCPA — что/зачем собирается.
- [ ] Детерминированный тест: DP-шум в пределах ε, unlinkability.

---

## 7. Рекомендация по умолчанию (если нет явного решения)

| Вопрос | Default |
|--------|---------|
| Модель угрозы | honest-but-curious сервер |
| Privacy budget | ε ≤ 1.0 на тенант в год, RDP accounting |
| Secure aggregation | отложить до enterprise |
| Compliance | GDPR (базовый уровень) |
| Ротация hash | каждые 7 дней |
| Federated | оставить, с disclaimer «beta, not for regulated industries» |
| TLS/pinning | внедрить немедленно (0.5 дня) |

---

## 8. Что НЕ делаем (scope exclusion)

- Не внедряем полный Secure Multiparty Computation (SMPC) — overkill до enterprise.
- Не делаем HIPAA-grade анонимизацию без явного запроса клиента.
- Не анализируем inference-атаки на глобальную модель (это отдельная экспертиза #3).
- Не делаем формальную DP-верификацию (mathematical proof) — достаточно implementation audit.
- Не мигрируем на PostgreSQL только ради federated (SQLite достаточно для MVP).

---

## 9. Чек-лист решений — ПРИНЯТО (13.08.2026)

| # | Вопрос | Решение |
|---|--------|---------|
| 1 | Модель угрозы | honest-but-curious сервер (primary) + MITM (secondary) |
| 2 | Privacy budget | ε ≤ 1.0 на тенант в год, **RDP accounting — формальный** |
| 3 | Secure aggregation | отложить до enterprise (>10 тенантов); сейчас ротация+RDP+DP-шум+disclaimer |
| 4 | Compliance | GDPR (базовый). CCPA следует за GDPR. HIPAA — out of scope |
| 5 | Ротация `tenant_hash` | ДА, 7-дневные эпохи (потеря долгосрочной истории допустима) |
| 6 | Federated до enterprise | оставить, disclaimer «beta, not for regulated industries» |
| 7 | TLS/pinning | **внедрить немедленно (0.5 дня)** |

**Уточнение к #1:** «honest-but-curious» — не «не доверяем своему серверу», а compliance-позиция:
даже собственный сервер обязан минимизировать/псевдонимизировать данные по GDPR Art. 25.
Формулировать именно так в compliance-документации.

**Уточнение к #2:** два порога бюджет-учёта:
- мягкий: ε_spent > 5.0 → предупредить тенанта (лог + флаг в статусе);
- жёсткий: ε_spent > 10.0 → стоп federated для тенанта.
Жёсткий стоп без предупреждения — плохой UX.

---

## 10. Порядок реализации (стоимость/ценность)

**Шаг 1 (немедленно, 0.5 дня): TLS + HMAC-подпись payload** — закрывает MITM (§3.4). Без этого
остальное бессмысленно (трафик открыт).

**Шаг 2 (3–5 дней, вариант B): ротация `tenant_hash` + RDP accounting** — закрывает linkability
(§3.1) + budget composition (§3.2). Один блок: оба используют BudgetAccountant.

**Шаг 3 (отложено, enterprise): Secure aggregation (Shamir)** — только при >10 тенантах. До тех
пор — disclaimer «beta» в UI/доках.

**Критерий готовности #2 к enterprise:** все пункты §6 закрыты + compliance-документация
(GDPR Art. 25). До этого federated работает только как «beta для нерегулируемых отраслей».

---

*Черновик. После решений по §9 — финализация, как по #1. Параллельно готовится экспертиза #3 (Inference Attacks on Global Model).*
