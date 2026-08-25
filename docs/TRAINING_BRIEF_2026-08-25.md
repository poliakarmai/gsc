# GSC Training Brief — 25.08.2026

> Для агента дообучения. **Доступа к репо нет** — весь нужный код приведён ниже.
> **Не отключать детекторы** — только уточнение/расширение.
> Два вопроса: (1) шумный FP-детектор `YAML-B39DC08C`, (2) слепое пятно `external-scan` (CI/IaC/SCA).

---

## Вопрос 1 — `YAML-B39DC08C`: шумный FP-детектор (12/12 ложных)

### Что это
- **rule_id:** `YAML-B39DC08C`, описание «Printing potentially sensitive data to stdout».
- Правило живёт в ТРЁХ местах (синхронизируются):
  1. `gsc-rules/sample.yml` — первоисточник (YAML).
  2. `gsc_core/gsc_yaml_rules.py` — встроенная копия правил (dict внутри Python).
  3. `gsc_core/gsc_detectors/yaml_rules/no_print_secrets.py` — автоген Python-детектор (рабочий).

### Код детектора (полностью)

**`gsc_core/gsc_detectors/yaml_rules/no_print_secrets.py`:**
```python
# Auto-generated from gsc-rules/sample.yml
# Rule: no-print-secrets — Printing potentially sensitive data to stdout

from ..base import RegexDetector

RULE_ID = "YAML-B39DC08C"
ECHELON = 2
NOISE_TIER = "custom"
description = """Printing potentially sensitive data to stdout"""

patterns = [["\\bprint\\s*\\(.*(?:password|secret|token|key|api_key)", "print() with sensitive variable"], ["\\blogging\\.\\w+\\(.*(?:password|secret|token|key|api_key)", "logging sensitive data"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-print-secrets",
    patterns=patterns,
    severity="HIGH",
    confidence=0.75,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
```

**`gsc_core/gsc_yaml_rules.py` (фрагмент, id="no-print-secrets"):**
```python
{
    "id": "no-print-secrets",
    "severity": "HIGH",
    "confidence": 0.75,
    "languages": ["python"],
    "message": "Printing potentially sensitive data to stdout",
    "patterns": [
        {"regex": r"\bprint\s*\(.*(?:password|secret|token|key|api_key)", "title": "print() with sensitive variable"},
        {"regex": r"\blogging\.\w+\(.*(?:password|secret|token|key|api_key)", "title": "logging sensitive data"},
    ],
    "fix": "Never log secrets. Use redacted logging: log.debug('Auth with key: %s', key[:4] + '***')",
},
```

**`gsc-rules/sample.yml` (фрагмент, id="no-print-secrets"):**
```yaml
- confidence: 0.75
  fix: 'Never log secrets. Use redacted logging: log.debug(''Auth with key: %s'', key[:4] + ''***'')'
  id: no-print-secrets
  languages:
  - python
  message: Printing potentially sensitive data to stdout
  patterns:
  - regex: \bprint\s*\(.*(?:password|secret|token|key|api_key)
    title: print() with sensitive variable
  - regex: \blogging\.\w+\(.*(?:password|secret|token|key|api_key)
    title: logging sensitive data
  severity: HIGH
```

### Проблема
Regex `\bprint\s*\(.*(?:password|secret|token|key|api_key)` матчит **любой** `print(...)`, в строке которого встречается слово `secret`/`password`/`token`/`key`/`api_key` — **без различения**:
- `print(api_key)` — реальная утечка (баг) ✅
- `print(f"[+] Scanning for secrets...")` — FP ❌ (литерал, слово "secret" в тексте диагностики)

Плюс контекстная слепота: `print(f"  {i}. {secret}")` в security-сканере — это **фича** (сканер должен показывать найденные секреты), а не утечка credentials в приложении. Детектор не различает приложение vs инструмент-сканер.

Корень: `.*` в regex — жадный, «прыгает» через любые символы между `print(` и словом `secret`, не проверяя, является ли `secret` реальной переменной или просто подстрокой литерала.

### Репродукция
```
git clone --depth 1 https://github.com/CyberNilsen/CyberSentry /tmp/gsc_target2
python3 gsc.py external-scan /tmp/gsc_target2 --profile audit --max-llm 25 -o /tmp/gsc_report3
```
Результат: **15 raw → 12 false_positive** (все 12 — `YAML-B39DC08C`), 3 uncertain. 0 confirmed/likely.

FP-строки в `cybersentry.py` (все — логи-диагностика, ни одна не выводит значение):
| строка | код |
|---|---|
| 59 | `print(f"{Fore.BLUE}[+] Scanning for secrets...{Style.RESET_ALL}")` |
| 113 | `print(f"{Fore.MAGENTA}[DEBUG] Found secret in: {source_name}...")` |
| 118 | `print(f"{Fore.CYAN}[i] Ignored false positive: {detector_name} - {display_secret[:20]}...")` |
| 126 | `print(f"{Fore.YELLOW}[!] Found {len(secrets_found)} potential secrets...")` |
| 129 | `print(f"  {i}. {secret}")` — вывод найденного секрета (фича сканера) |
| 131/133/136/186/189/191/240 | аналогичные логи-строки |

Полный файл цели `cybersentry.py` (255 строк) — приложен отдельным файлом `cybersentry.py` рядом с этим брифом.

### Что нужно (дообучение, НЕ отключение)
1. **Различать аргумент `print`:** срабатывать, только если аргумент — идентификатор/выражение с переменной (не строковый литерал с вкраплённым словом). Убрать match, когда в кавычках литерал вида `"...secret..."` без интерполяции реального значения.
2. **Контекстный фильтр «инструмент-сканер»:** понижать/маркировать, если файл/проект — security-сканер (вывод найденных секретов — его функция).
3. **Требовать соседство реального credential-паттерна:** `api_key = ...`, `password = ...`, `token = ...` присваивание выше по коду, а не просто слово в тексте.
4. Опционально — снизить `noise_tier`/confidence или добавить позитивный/негативный пример в ground-truth trainer.

Конкретная техника: вместо `\bprint\s*\(.*(?:password|secret|...)` — негативный lookahead на строковый литерал:
```
\bprint\s*\(\s*(?!["'])(?:(?!\b(?:password|secret|token|key|api_key)\b).)*[A-Za-z_][A-Za-z0-9_]*(?:password|secret|token|key|api_key)
```
(срабатывает только если sensitive-токен — это идентификатор переменной, а не подстрока в кавычках).

### Данные для обучения
- FP-примеры: `/tmp/gsc_report3/scan.json` (12 записей `YAML-B39DC08C` + LLM-вердикт).
- Уже замечен как шум: `benchmark/precision_report_batch5.json` (`YAML-B39DC08C: HIGH: 2`).
- LLM-revalidate отклоняет все 12 → жжёт бюджет (~13 LLM-вызовов на мусор). Аргумент за уточнение regex до LLM-этапа.

---

## Вопрос 2 — `external-scan` слеп к CI/IaC/SCA

### Что это
`python3 gsc.py external-scan <repo>` сканирует **только python-код**. На CyberSentry: `6/36 files scanned`, `languages: python`. `.github/workflows/*.yml`, IaC (`*.tf`, Dockerfile), SCA — не попадают в скан (даже с `--profile audit`).

### Проблема
Пропускаются реальные supply-chain-находки в CI:
- `curl -sSfL <url> | sh` — непроверенный удалённый скрипт (remote code exec при деплое).
- GitHub Actions без digest-SHA (`checkout@v4`, `setup-python@v5`, `github-script@v7`) — S-05/S-06 (unpinned action).

### Репродукция
`CyberSentry/.github/workflows/security.yml` (приложен файлом `security.yml`):
```yaml
# строка 25 — remote script exec без проверки SHA:
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# строки 16/19/36/43 — actions без digest:
uses: actions/checkout@v4
uses: actions/setup-python@v5
uses: actions/upload-artifact@v4
uses: actions/github-script@v7
```

### Что нужно
1. **Расширить языковой фильтр `external-scan`** на CI workflows (`.github/workflows/*.yml`, `.gitlab-ci.yml`), IaC (`*.tf`, `Dockerfile*`, `k8s/*.yaml`), SCA-манифесты (`requirements.txt` без пинов, `package.json`).
2. **Подключить существующие модули** к `external-scan` (или задокументировать отдельный pipeline): `gsc_iac`, supply-chain S-05/S-06 (action pin по SHA уже реализованы — проверить, почему не вызываются).
3. Как минимум — **честный отчёт**: если скан не покрывает CI/IaC/SCA, это должно быть явно в summary, а не молчаливый «6/36 files».

---

## Что НЕ делать
- ❌ **Не отключать** `YAML-B39DC08C` (прямое указание владельца).
- ❌ Не снижать порог ревалидации «в лоб» — только уточнение паттернов/контекста.
- ❌ Не выкидывать CI/IaC из scope — наоборот, расширять покрытие.

## Готовность (критерии)
- [ ] `YAML-B39DC08C`: 12 FP из репро → 0 FP при сохранении детекции реальных `print(api_key)` (регрессия на `calibration/` + `OWASPBenchmark`).
- [ ] `external-scan` на CyberSentry видит `security.yml` и репортит `curl | sh` + unpinned actions (S-05/S-06).
- [ ] Полный `pytest` зелёный, Judge (rejudge CLI) на изменениях.
