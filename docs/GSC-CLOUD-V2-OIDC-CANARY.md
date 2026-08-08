# GSC Cloud v2 — OIDC Worker + Canary Deploy

> Дизайн-документ. На основе книги Брикмана «Основы DevOps», гл. 5 (CI/CD), гл. 8 (Безопасность), гл. 9 (Данные).

## Состояние сейчас

```
GitHub App → installation token → clone → GSC scan → PR comment + check run
```

Проблемы:
1. **Долгоживущие installation tokens** — токен живёт пока крутится worker
2. **Прямой деплой в прод** — новые детекторы → сразу 100% сканов → могут сломать всю систему
3. **Нет observability** — scan_queue не даёт метрик (p95 latency, error rate)

---

## 1. OIDC для Worker'ов

### Текущая архитектура
```
GitHub App private key → generate JWT → exchange for installation token
                                                         ↓
                                              token живёт 1 час
```

### Целевая архитектура (OIDC)

```
GitHub Actions / GSC worker
        ↓
   OIDC token (JWT от GitHub Actions, живёт 5 мин)
        ↓
   AWS STS AssumeRoleWithWebIdentity
        ↓
   Временные креды AWS (15 мин — 1 час)
        ↓
   Доступ к S3/Secrets Manager/DynamoDB
```

**Выигрыш:**
- Нет долгоживущих токенов — даже если скомпрометирован worker, креды истекут через 15 минут
- Нет секретов в env — OIDC provider сам выдаёт временные креды
- Аудит — CloudTrail логирует каждую операцию AssumeRoleWithWebIdentity

### Реализация (3 шага)

**Шаг 1: OIDC Provider в AWS**
```hcl
# terraform/gsc-oidc.tf
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "gsc_worker" {
  name = "gsc-worker-oidc"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub": "repo:poliakarmai/gsc:*"
        }
      }
    }]
  })
}
```

**Шаг 2: GitHub Actions Workflow**
```yaml
# .github/workflows/gsc-worker-oidc.yml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # ← нужно для OIDC
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/gsc-worker-oidc
          aws-region: us-east-1
      - run: python3 -m cloud.worker  # креды уже в env
```

**Шаг 3: Убрать installation tokens**
- `cloud/github_auth.py`: `get_installation_token()` → deprecated
- Вместо: worker получает креды через OIDC + AWS STS
- GitHub App ключ → только в Secrets Manager, не в CI переменных

---

## 2. Canary-деплой новых детекторов

### Проблема
Новый детектор (GS032, GS033) → сразу в прод → если FP-шторм → все пользователи страдают.

### Решение: Canary rollout

```
Деплой нового детектора
        ↓
  Этап 1: 5% сканов (canary) — 24 часа
        ↓ мониторинг: FP rate, p95 latency, error rate
        ↓
  Этап 2: 25% сканов — 24 часа
        ↓
  Этап 3: 100% сканов (full rollout)
```

### Реализация через feature flags

```python
# cloud/feature_flags.py
CANARY_DETECTORS = {
    "GS032": {"pct": 5, "since": "2026-08-08", "min_confidence": 0.70},
    "GS033": {"pct": 5, "since": "2026-08-08", "min_confidence": 0.70},
}

def is_canary_enabled(detector_id: str, repo_hash: str) -> bool:
    """Deterministic canary: hash(repo + detector) % 100 < pct"""
    flag = CANARY_DETECTORS.get(detector_id)
    if not flag:
        return True  # не в канарейке → полный доступ
    bucket = hash(f"{repo_hash}:{detector_id}") % 100
    return bucket < flag["pct"]
```

**Canary promotion:**
```bash
# Повысить GS032 с 5% до 25%
python3 -m cloud.canary promote GS032 --pct 25

# Откатить GS032 (FP-шторм)
python3 -m cloud.canary rollback GS032

# Показать статус всех канареек
python3 -m cloud.canary status
```

### Мониторинг канарейки

```python
# cloud/canary.py — метрики для CloudWatch
CANARY_METRICS = {
    "fp_rate": "FP count / total findings for canary detector",
    "p95_latency": "p95 scan time for repos with canary detector",
    "error_rate": "exceptions / total scans with canary detector",
    "promotion_ready": "fp_rate < 5% AND error_rate < 1% for 24h",
}
```

---

## 3. Observability (SLO/SLI)

Добавить метрики в `cloud/observability.py`:

```python
SLO = {
    "availability": 99.9,        # 8.7h downtime/year max
    "p95_scan_latency": 30.0,    # секунд
    "error_rate": 0.01,          # 1%
    "fp_rate": 0.05,             # 5% — триггер для canary rollback
}

# Prometheus-метрики
scan_duration_seconds = Histogram("gsc_scan_duration_seconds", ...)
scan_errors_total = Counter("gsc_scan_errors_total", ...)
canary_findings_total = Gauge("gsc_canary_findings_total", ...)
```

---

## План внедрения

| Фаза | Задача | Дней |
|------|--------|------|
| 1 | OIDC Provider + IAM Role (Terraform) | 1 |
| 2 | Worker OIDC интеграция | 2 |
| 3 | Canary feature flags (cloud/feature_flags.py) | 2 |
| 4 | Canary promotion CLI (cloud/canary.py) | 1 |
| 5 | CloudWatch метрики + алерты | 2 |
| 6 | Документация (DESIGN.md обновить) | 1 |

---

> *«Безопасно по умолчанию — не опция, а требование. Если ты не можешь доказать что система безопасна, она небезопасна.»* — Евгений Брикман, 2026
