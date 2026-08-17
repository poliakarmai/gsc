# Бриф: улучшение детектора GS022 (Open Redirect) в GSC

> Для внешнего AI-агента (Claude Code / Codex / ChatGPT). **Самодостаточный** — код детектора
> вшит ниже, доступ к репозиторию не нужен. Верни только предложения в формате из §6.

---

## 1. Контекст

GSC — self-learning SAST-платформа (Python, 41 детектор). Детекторы — это regex-паттерны +
контекстные фильтры. **Текущая боль — precision, не recall**: на 10 реальных проектах 2695
находок, precision CRITICAL ~8–12%. Задача — убрать ложные срабатывания (FP) **без потери**
истинных (TP).

Детектор GS022 ловит Open Redirect (CWE-601): редиректы на URL из пользовательского ввода,
обходы валидации URL.

## 2. Текущий код детектора (меняй только паттерны/фильтры, не контракт)

```python
# gs022_open_redirect.py
from __future__ import annotations
import re
from pathlib import Path
from . import AuditContext, Detector, Finding

RULE_ID = "GS022"
ECHELON = 2
NOISE_TIER = "normal"
description = "Open Redirect / URL Manipulation — redirect params, validation bypass"

OPEN_REDIRECT_PATTERNS: list[tuple[str, str, str]] = [
    (r'redirect\s*\(\s*(?:request\.(?:args|form|query|params)|params\[|req\.(?:query|body))',
     "Open Redirect: redirect() with user-controlled URL", "HIGH"),
    (r'redirect\(.*\$_(?:GET|POST|REQUEST)', "Open Redirect: PHP redirect with user input", "CRITICAL"),
    (r'(?-i:Redirect\s*\(\s*Request)', "Open Redirect: ASP.NET Redirect with Request", "CRITICAL"),
    (r'redirect_to\s+.*(?:params|request)', "Open Redirect: Rails redirect_to with params", "HIGH"),
    (r'window\.location\s*=\s*.*(?:url|redirect|next|callback|return)', "Open Redirect: JS window.location with redirect param", "MEDIUM"),
    (r'window\.location\.(?:href|replace)\s*=\s*.*(?:url|redirect|next|callback)', "Open Redirect: JS location change with redirect param", "MEDIUM"),
    (r'HttpResponseRedirect\s*\(.*request', "Open Redirect: Django redirect with request data", "HIGH"),
    (r'request\.(?:args|form|query|params)\.get\s*\(\s*[\"\'](?:redirect|url|next|return|callback|goto|redir|continue|target)[\"\']',
     "Open Redirect: redirect/url/next param extracted from request", "HIGH"),
    (r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\"\'](?:redirect|url|next|return|callback|goto|redir)[\"\']',
     "Open Redirect: PHP redirect param from user input", "CRITICAL"),
    (r'url\.startswith\s*\(\s*[\"\']/', "Weak URL validation: only checks for leading /", "MEDIUM"),
    (r'urlparse|url\.parse|URL\(', "URL parsing present — verify whitelist, not blacklist", "INFO"),
    (r'\.replace\s*\(\s*[\"\']https?://[\"\']\s*,\s*[\"\']', "Weak URL validation: simple string replace", "MEDIUM"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.go', '.java', '.cs'}
EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__'}
EXCLUDE_PATTERNS = ['test_', 'test/', '.test.', '.spec.', '__test__']

def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    files = _collect_files(ctx.path)
    for file_path in files:
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue
        rel_path = str(file_path.relative_to(ctx.path))
        for pattern, message, severity in OPEN_REDIRECT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category=severity,
                    title=message, file_path=rel_path, line=line_no,
                    detail=snippet.strip()[:200], cwe="CWE-601",
                    cvss={"CRITICAL":"8.1","HIGH":"6.1","MEDIUM":"4.3","INFO":"0.0"}.get(severity,"4.3"),
                ))
    return findings

def _collect_files(root: Path) -> list[Path]:
    files = []
    for ext in FILE_EXTENSIONS:
        for f in root.rglob(f'*{ext}'):
            if any(d in f.parts for d in EXCLUDE_DIRS):
                continue
            if any(p in f.name for p in EXCLUDE_PATTERNS):
                continue
            files.append(f)
    return files

def _extract_line(content: str, line_no: int) -> str:
    lines = content.split('\n')
    return lines[line_no - 1] if 0 < line_no <= len(lines) else ''

def _is_false_positive(snippet: str) -> bool:
    s = snippet.strip()
    if s.startswith('//') or s.startswith('#') or s.startswith('/*') or s.startswith('*'):
        return True
    if s.startswith('<!--'):
        return True
    # Django redirect(request.path / get_full_path) — редирект на тот же путь
    if re.search(r'redirect\s*\(\s*request\.(?:path|get_full_path|path_info)', s, re.I):
        return True
    return False
```

## 3. Метрика — что считаем «лучше»

- **Primary: precision** = TP/(TP+FP). Убрать FP **без потери TP**.
- **Guard:** любое сужение/отключение паттерна допустимо только если TP-кейсы остаются.
- Recall (новые паттерны) — вторично, и только после того как precision устаканился.

## 4. Известные FP-кандидаты (зацепки — проверь и подтверди/опровергни)

1. **INFO-шум (`urlparse|url\.parse|URL\(`)**: матчит любой легитимный `from urllib.parse import urlparse`
   или JS `new URL(...)` вообще без redirect-контекста. Генерит INFO на то, что не уязвимость.
   Кандидат: сузить до redirect-контекста или убрать INFO-тир.
2. **`HttpResponseRedirect(...request.get_full_path())`**: фильтр `_is_false_positive` покрывает
   только `redirect(request.get_full_path())`, но НЕ `HttpResponseRedirect(...)`. Django-редирект на
   тот же путь проходит как HIGH FP.
3. **ASP.NET `Redirect(Request...)`**: паттерн не различает `Request["url"]` / `Request.QueryString["..."]`
   (user-controlled = TP) от `Request.Url.AbsoluteUri` / `Request.UrlReferrer` (не user-controlled = FP).
4. **`request.args.get('next')` без safe-проверки**: паттерн матчит само извлечение параметра, даже
   если следом идёт валидация `url_has_allowed_host_and_scheme` / `is_safe_url` / `allowed_hosts`.
   Нужен context: если safe-валидация есть в ±3 строках — skip.

## 5. Твоя задача

Проанализируй код выше. Для каждого из 4 кандидатов §4 (и любых ДРУГИХ FP, которые заметишь)
предложи конкретное решение. Три допустимых инструмента (в порядке предпочтения):

1. **Path exclusion** — добавить в `EXCLUDE_PATTERNS`/`EXCLUDE_DIRS` (тесты, samples, vendor).
2. **Regex-сужение** — потребовать больше контекста в самом паттерне.
3. **Context analysis** — расширить `_is_false_positive` (или заменить на просмотр ±3 строк).

## 6. Формат ответа (строго)

Для каждого предложения — блок:

```
### GS022: <название>
- Тип: path_exclusion | regex_сужение | context_analysis
- Паттерн/код: <конкретный regex или diff>
- Обоснование: почему это FP (пример файла/строки)
- Пример FP, который убирает: <реальная строка кода>
- Влияние на TP: какие TP-кейсы НЕ задевает
```

## 7. Что НЕ делать

- ❌ Не менять `RULE_ID`, severity-шкалу, сигнатуру `detect()`, ключи `Finding`.
- ❌ Не отключать детектор целиком — только фильтры.
- ❌ Не «чистить код» сверх задачи (scope discipline).
- ❌ Не предлагать без примеров FP (нельзя оценить risk/benefit).
