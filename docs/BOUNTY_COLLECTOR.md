---
title: "GSC Bounty Collector v2"
date: 2026-08-11
status: active
type: gsc-feature
---

# 🎯 GSC Bounty Collector v2

> Превращает self-learning из «обучения на вердиктах» в «обучение на реальных размеченных уязвимостях».

## Архитектура

```
GHSA API (публичный, без авторизации)
  │
  ├─→ GhsaCollector
  │     ├─ filter: ecosystem (pip/npm/go/cargo)
  │     ├─ rank_hunks_by_cwe(): 19 CWE × keyword scoring
  │     ├─ extract top hunk → vulnerable_code + fixed_code
  │     ├─ ±5 строк контекста вокруг hunk'а
  │     ├─ fix_quality: fix / patch / workaround
  │     ├─ pattern_hash: дедупликация по нормализованному коду
  │     └─ save → bounty_examples
  │
  ├─→ NegativeCollector
  │     ├─ cross-CWE: примеры других CWE того же языка
  │     ├─ sibling-file: clean-файлы из parent-коммита репо
  │     └─ save → negative_examples
  │
  └─→ Дашборд
        └─ CWE × language матрица готовности к автогенерации

Bugcrowd VRT API (публичный JSON)
  │
  └─→ VrtCollector → 581 категория → vrt_categories
```

## Таблицы БД

### `bounty_examples` (v2)

| Колонка | Тип | Описание |
|---------|-----|----------|
| `ghsa_id` | TEXT | GitHub Security Advisory ID |
| `cwe_id` | TEXT | CWE-79, CWE-89, ... |
| `language` | TEXT | python / javascript / go / rust |
| `vulnerable_code` | TEXT | Удалённые строки из security-relevant hunk'а |
| `fixed_code` | TEXT | Добавленные строки |
| `fix_context` | TEXT | ±5 строк контекста вокруг изменения |
| `fix_quality` | TEXT | fix / patch / workaround |
| `pattern_hash` | TEXT | Нормализованный хеш для дедупликации |
| `hunk_relevance` | REAL | 0.0–1.0, CWE keyword overlap score |
| `language_version` | TEXT | Диапазон версий (из GHSA) |

### `negative_examples`

| Колонка | Тип | Описание |
|---------|-----|----------|
| `cwe_id` | TEXT | Для какого CWE это отрицательный пример |
| `language` | TEXT | Язык |
| `clean_code` | TEXT | Код БЕЗ этой уязвимости |
| `source_file` | TEXT | Откуда взят |

## Три слоя применения

### 1. BountyLoader — retrieval-based enrichment

```python
from gsc_bounty_loader import BountyLoader
loader = BountyLoader()

# Proof-of-Fix few-shot
fixes = loader.get_few_shot_fixes("CWE-88", "python", k=3)
prompt = loader.build_pof_prompt("CWE-88", "python", vulnerable_code)

# Deep Reduce enrichment (retrieval, не all-by-language)
examples = loader.get_relevant_examples(code_snippet, "javascript", k=3)

# Revalidator context
context = loader.get_finding_context(finding_detail, "python")
```

### 2. Deep Reduce — автоматически

`gsc_deep_reducer.py` при сканировании каждого файла:
1. Определяет язык по расширению
2. Вызывает `load_bounty_context(filepath, code_snippet)` 
3. Внедряет top-3 релевантных примера в промпт
4. Few-shot prompting: «вот как выглядит реальная уязвимость → вот как исправили»

### 3. Auto-Detector — validation gate

```bash
# Проверить готовность
python3 scripts/gsc_auto_detector.py --check

# Валидация train/test
python3 scripts/gsc_auto_detector.py --validate

# Генерация + shadow-активация
python3 scripts/gsc_auto_detector.py --generate
```

**Validation flow:**
```
5+ примеров CWE+lang + 3+ fix-качества + 1+ отрицательный
  ↓
train (80%) / held-out (20%) split
  ↓
Генерация паттернов из train
  ↓
TP-check: held-out ≥ 80%? ───┐
FP-check: clean проекты = 0? ─┤
  ├── PASS → SHADOW-детектор (собирает вердикты, не блокирует)
  │           ↓
  │      ≥10 вердиктов + TP ≥ 70%
  │           ↓
  │      FULL DETECTOR (через Blocking Engine)
  │
  └── FAIL → ждём больше примеров
```

## CWE → Hunk Keywords (19 карт)

```python
CWE_HUNK_PATTERNS = {
    "CWE-22":  [path, os.path, ../, open(, readfile, traversal],
    "CWE-79":  [innerHTML, sanitize, escape, dangerously, DOMPurify],
    "CWE-88":  [argument injection, check_unsafe, allow_unsafe],
    "CWE-89":  [SELECT, INSERT, parameterize, placeholder, execute],
    "CWE-918": [SSRF, request url, fetch(, internal IP, validate url],
    "CWE-1333":[ReDoS, backtracking, exponential, regex, pattern],
    # ... +13 more
}
```

## Дашборд

```bash
python3 gsc_collect_bounty.py dashboard
```

```
CWE          Lang          Examples    Fix    W/A   Neg  Ready
-----------------------------------------------------------------
CWE-88       python               3      2      0     1 ⚠️  2 more
CWE-79       javascript           2      0      1     0 ⚠️  3 more
...
📈 Working toward 5+ examples per CWE+lang...
   Total: 15 positive | 0 negative | 12 unique CWEs
   Public data (GHSA) — no DP needed ✓
```

## Ночной пайплайн

```bash
# 04:00 MSK — cron 5ad3ea081b84
cd ~/gsc

# 1. Self-learning
python3 gsc.py revalidate . --json

# 2. NVD + GitHub patterns
python3 gsc_collect_light.py nvd && python3 gsc_collect_light.py github

# 3. Bounty Collector v2
python3 gsc_collect_bounty.py all          # GHSA + VRT + negatives

# 4. Auto-Detector check
python3 scripts/gsc_auto_detector.py --check

# 5. Batch Revalidate (с bounty-контекстом)
python3 scripts/batch_revalidate.py --fetch 500 --context > /tmp/reval.json

# 6. Federated Submit
python3 scripts/federated_submit.py
```

## Ключевые файлы

| Файл | Назначение |
|------|-----------|
| `gsc_collect_bounty.py` | Коллектор v2: GHSA, VRT, negative, dashboard |
| `gsc_bounty_loader.py` | Retrieval-движок: PoF few-shot, Deep Reduce, Revalidator |
| `gsc_deep_reducer.py` | Deep Reduce с retrieval-based enrichment |
| `scripts/gsc_auto_detector.py` | Авто-генератор с validation gate |
| `scripts/batch_revalidate.py` | Ревалидатор с `--context` флагом |

## Принципы

1. **Публичные данные — нет DP.** GHSA и Bugcrowd VRT — открытые данные. Никакой differential privacy.
2. **Retrieval, не all-by-language.** Для каждого сниппета — keyword overlap + CWE matching, не все примеры языка.
3. **Shadow before blocking.** Сгенерированное правило = SHADOW. Вердикты → статистика → промоушн.
4. **Fix quality matters.** Не каждый фикс в GHSA — правильный фикс. workaround ≠ fix.
5. **Дедупликация по паттерну, не по ID.** Разные advisory могут описывать один и тот же паттерн.

## Состояние на 11.08.2026

- 15 положительных примеров (Python 7, JS 6, Go 2)
- 0 отрицательных (запуск с nightly)
- 14 уникальных CWE
- 0 готовых к автогенерации комбо (нужно 5+)
- Прогноз: ~2 недели до первого shadow-детектора
