# Бриф: улучшение детекторов GSC

> Передаётся AI-агенту (Claude Code / Codex / саб-агенту). Самодостаточный: содержит контекст,
> контракт, метрику и формат ответа. **Не проси «улучшить всё» — давай по одному детектору.**
> Обновлён 24.08.2026 (раунды 2–3: GS001/GS020/GS025 частично закрыты; Clean FP 114→106).

---

## 1. Что такое GSC

GSC (Git Security Checker) — self-learning AppSec-платформа, **50 детекторов (46 registry + 4 движка:
Secrets/SCA/IaC/Invariants)**, schema v33, v1.4.0, 211 модулей. Полный цикл
`detect → prove → fix → verify → heal → predict`.
Репозиторий: `~/gsc`. Детекторы: `gsc_core/gsc_detectors/gsXXX_*.py`.
SSOT чисел: `python3 gsc_meta.py`. Сверка: `python3 scripts/gsc_reconcile.py`.

**Текущая боль — precision, не recall.** Замер 4 (24.08, 45 проектов): CRITICAL 498 (было 4 302),
HIGH 1 324 (было 37 246). Главные исторические FP-источники закрыты: GS008 eval (2 508→0,
`ba4c2d0`+severity), GS000-LEGACY (505→7), GS005 SQLi (4 258→29, downgrade всех интерполяций).
Clean FP на calibration-сете: 114 → 106 (раунды 2–3). Лидер CRITICAL-шума — **GS001
hardcoded secrets (4 920 CRITICAL по свежему срезу БД)**; GS020 XSS и GS025 AI-provenance —
следующие по HIGH-шуму.

## 2. Контракт детектора (что НЕЛЬЗЯ ломать)

Каждый registry-детектор — файл `gsXXX_name.py`. **Реальный контракт** (не legacy-сигнатура):

```python
from . import AuditContext, Finding

RULE_ID = "GS005"          # НЕ менять
ECHELON = 2
description = "..."

def detect(ctx: AuditContext) -> list[Finding]:
    if RULE_ID in ctx.skipped_detectors:
        return []
    findings = []
    for fp in ctx.get_source_files(extensions=(...)):   # или ctx.get_files()
        content = fp.read_text()
        ...   # regex-матчинг, фильтры
        findings.append(Finding(
            rule_id=RULE_ID, file_path=rel_path, line=..., severity="...",
            title="...", detail="...", fix_suggestion="...", noise_tier="...",
        ))
    return findings
```

**Инварианты (нарушение = откат):**
1. **`rule_id` не менять.** `finding_key = sha256(rule_id + file + snippet)[:12]` — стабилен, ломает
   существующие находки и self-learning.
2. **Ключи finding:** `file_path` / `line` / `detail` / `severity` (+ `noise_tier`). Собирать через
   `Finding(...)` или `make_finding()`, НЕ dict руками.
3. **Новый паттерн → `pattern_id` в metadata** (если детектор с per-pattern tracking), НЕ новый rule_id.
   **ВАЖНО:** добавляя новый паттерн в секцию `patterns=[...]`, ставь его **в конец секции** — иначе
   сдвинется нумерация `GS0XX-<TYPE>-<LANG>-<N>` и сломаются hardcoded pid-ссылки
   (напр. `_INTERPOLATION_REQUIRED = {"GS005-GEN-PY-008"}`). Реальный баг этой сессии.
4. **Skip/negative-паттерн обязан пересекать переносы строк** (`[\s\S]*` / `re.DOTALL`), если
   положительный паттерн использует `\s*` — иначе skip не сработает.
5. **Scoped case-sensitivity:** Python `re` не поддерживает голый `(?-i)`. Только `(?-i:...)`.

## 3. Метрика — что считаем «лучше»

- **Primary: precision** = TP/(TP+FP). Задача — убрать FP **без потери TP**.
- **Guard:** отключение/сужение паттерна допустимо только если TP-кейсы остаются (TPR drop ≤ 3%).
- **Recall (новые паттерны) — вторично.** Только после того, как precision устаканился; каждый
  новый паттерн обязан пройти clean-репозитории (не дать FP).

## 4. Три инструмента (в порядке предпочтения)

1. **Path exclusion** — `EXCLUDE_PATH_RE`/`EXCLUDE_FILE_RE`: тесты/samples/tutorials/vendor/mock
   не сканируются этим детектором. Дёшево, безопасно, снимает 30–60% FP разом.
2. **Regex-сужение** — требовать больше контекста: SQL-оператор перед `SELECT`, `%`-оператор после
   `%s` (интерполяция vs DBAPI-placeholder), слово целиком `\bkey\b` вместо подстроки `key`.
3. **Context analysis** — ±N строк вокруг матча: sanitizer (escape/htmlEscape/DOMPurify) → LOW,
   taint-source (request.args/input()) → HIGH, параметризованный запрос → skip.

## 5. Приоритетные детекторы (текущая очередь)

| Детектор | Файл | Шум (свежий срез БД) | Статус / зацепка |
|---|---|---|---|
| GS001 hardcoded secret | `gsc_core/gsc_detectors/gs001_hardcoded_secret.py` | 4 920 CRITICAL | 🔧 частично: числовые пароли + connection-string placeholder + public-key. Осталось: API-key/token паттерны, PAN/IBAN на ID |
| GS020 XSS/template | `gsc_core/gsc_detectors/gs020_*.py` | 2 275 HIGH + 68 CRIT | 🔧 частично: `dangerouslySetInnerHTML` без taint. Осталось: reflected/stored без user-input |
| GS025 AI-provenance | `gsc_core/gsc_detectors/gs025_*.py` | 1 969 HIGH | ✅ eval_usage→LOW + static eval→suppress. Осталось: insecure_defaults |
| GS004 subprocess/shell | `gsc_core/gsc_detectors/gs004_*.py` | 443 CRIT + 704 HIGH | 🔧 частично: os.system без taint→MEDIUM. Осталось: shell=True static |

> Уже закрыто (не брать повторно): GS005 SQLi (downgrade всех интерполяций, `c2cd2a5`), GS018 payment
> (negative lookahead `*100`), GS014 credential exposure (suppress log/debug), GS008 eval
> (`ba4c2d0` + CRITICAL→HIGH), GS000-LEGACY (remap в INFO/MEDIUM), GS017 weak passwords (`6691959`),
> GS002 world-readable (`e50afca`), GS029 secrets. Полная история — `docs/DETECTOR_TRAINING_STATUS.md`.

## 6. Что прочитать перед правкой

- `docs/DETECTOR_TRAINING_STATUS.md` — журнал фиксов + уроки + очередь.
- `benchmark/PRECISION_REPORT_100.md` — замер на 100 проектах (главный источник шума).
- `benchmark/FP_CLASSIFICATION.md` — классификация FP по детекторам (root-cause).
- `tests/test_regression.py` — регрессия (standalone, `python3 tests/test_regression.py`).
- `tests/test_compliance_secrets.py` — standalone compliance.
- Живой срез шума:
  `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE category IN ('CRITICAL','HIGH') GROUP BY rule_id, category ORDER BY COUNT(*) DESC;"`

## 7. Формат ответа (что вернуть)

Для **каждого** предложения — блок:

```
### GS-XXX: <название фильтра>
- **Тип:** path_exclusion | regex_сужение | context_analysis
- **Паттерн/код:** <конкретный regex или diff>
- **Обоснование:** почему это FP, откуда (пример файла/строки)
- **Пример FP, который убирает:** <реальная строка>
- **Влияние на TP:** какие TP-кейсы из ghsa_benchmark.py НЕ задевает
- **Предлагаемый regression-тест:** run_case(...) в tests/test_regression.py
```

Без этих 6 полей предложение не рассматривается (нельзя оценить risk/benefit).

## 8. Критерии приёмки (Definition of Done)

- [ ] Каждый фильтр подкреплён примером FP и проверкой TP (ghsa_benchmark).
- [ ] `rule_id` и `finding_key` не изменились.
- [ ] Regression-тест добавлен и зелёный (`python3 tests/test_regression.py`).
- [ ] Полный `python3 -m pytest -q` зелёный (+ `tests/test_compliance_secrets.py`).
- [ ] Re-scan целевого проекта: счётчик FP по rule_id снизился, TP не исчезли.
- [ ] `python3 scripts/gsc_reconcile.py` → ALL MATCH.

## 9. Что НЕ делать

- ❌ Не менять rule_id / finding_key / severity-шкалу.
- ❌ Не добавлять новый детектор (это отдельная задача, другой контракт).
- ❌ Не «чистить код» сверх задачи (scope discipline).
- ❌ Не отключать шумный детектор целиком — только фильтры (правило пользователя).
- ❌ Не редактировать regex-файлы через patch-tool вслепую (рвёт спецсимволы/`\s` → SyntaxError);
  для regex-правок — `write_file` или python `str.replace` (см. скилл `safe-code-editing`).
- ❌ **НЕ suppress слабые пароли `admin` / `admin123` / `root` / `guest` / `test` / `test123`**
  (напр. через `_WEAK_PASSWORD_VALUES`). Это **TP** в calibration: `tests/test_regression.py::t14`
  (`password="admin123"`), vuln-flask (`admin123`), pygoat. Предлагалось 3 раза подряд и 3 раза
  отбито — это не случайность, а граница recall, которую двигать нельзя.
- ❌ **НЕ suppress AWS example key `AKIAIO...MPLE`** — это позитивный TP-guard
  `tests/test_gs001_hardcoded_secret.py::test_aws_key_still_detected` (детектор обязан его ловить).
  Разрешается suppress только `-----BEGIN` (публичный ключ/сертификат).

## 10. Уроки этой сессии (обязательно учесть)

- **Docstring-фильтр `gsc_cli/main.py:_line_is_comment_or_docstring`** ложно режет находки ниже
  строки, где закрывающая тройная кавычка в выражении (`''' % request.url`) принята за открытие
  docstring. При работе с «находки пропадают в CLI, но детектор их выдаёт» — проверяй этот фильтр.
- **Отладка recall/FP по трём слоям:** детектор напрямую → `check_plugin_detectors` →
  `run_audit_echelons`. Если детектор ловит, а CLI нет — пост-фильтры (docstring/inline-suppress).
- **Перезамер precision** — `python3 scripts/gsc_precision_measure.py` (13 calibration проектов,
  ~2.5 мин). Не гоняй 100-проектный benchmark без нужды — дорого.
- **Карантин CRITICAL (active=2):** trainer деактивирует FP-генератор через `active=2`
  (soft-disable), НЕ `active=0` — если видишь `active=2`, это паттерн на ручном подтверждении.
  Учитывай: `active=1` (активен) ≠ `active=2` (карантин) ≠ `active=0` (выключен).
- **Типизированный root-cause:** `fp_log.reason` берётся из словаря `FP_REASONS`
  (too-broad/wrong-semantics/missing-context/third-party/ground-truth-fp) — атрибутируй причину,
  а не симптом «детектор шумит».
- **Демонстративные assert'ы:** в тестах проверяй конкретный title-keyword + `rule_id`, а не
  `len(findings)==1` (проходит при любом срабатывании). Пример — `tests/test_regression.py::t16`.
