# Бриф: улучшение детектора GS020 (XSS / HTML / Template Injection)

> Для внешнего AI-агента без доступа к репозиторию. Код детектора вшит ниже.
> Задача — снизить FP (false positives) **без потери TP** (recall/TP должен остаться константным).
> Работай ТОЛЬКО с реальными паттернами кода ниже, не придумывай кейсы, которых нет в паттернах.

## Контекст

GSC (Git Security Checker) — AppSec-сканер. GS020 ловит XSS / HTML injection / SSTI.
**Известная проблема**: 0% TPR на Java/JSP (нет Java-паттернов), и FP на статичных присваиваниях `innerHTML` / `eval()`.

Файл: `gsc_core/gsc_detectors/gs020_xss_injection.py`. Rule ID `GS020`, ECHELON 1, CWE-79 (XSS) / CWE-94 (SSTI) / CWE-80 (HTML injection).

## Код детектора (актуальный)

```python
XSS_PATTERNS: list[tuple[str, str, str]] = [
    # DOM XSS — dangerous sinks
    (r'\.innerHTML\s*=', "DOM XSS: .innerHTML assignment — use .textContent instead", "HIGH"),
    (r'dangerouslySetInnerHTML', "DOM XSS: dangerouslySetInnerHTML in React", "HIGH"),
    (r'\.outerHTML\s*=', "DOM XSS: .outerHTML assignment", "HIGH"),
    (r'document\.write\s*\(', "DOM XSS: document.write() with user input", "HIGH"),
    (r'\.insertAdjacentHTML\s*\(', "DOM XSS: insertAdjacentHTML()", "HIGH"),
    (r'eval\s*\(\s*[\"\'\`]', "DOM XSS: eval() with string input", "CRITICAL"),
    (r'setTimeout\s*\(\s*[\"\'\`]', "Potential DOM XSS: setTimeout with string argument", "MEDIUM"),
    (r'setInterval\s*\(\s*[\"\'\`]', "Potential DOM XSS: setInterval with string argument", "MEDIUM"),

    # Reflected XSS — unsanitized output
    (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[', "Reflected XSS: direct output of user input in PHP", "CRITICAL"),
    (r'print\s*\(\s*request\.(?:args|form|values|json)\[', "Reflected XSS: Flask request parameter in output", "HIGH"),
    (r'<%=.*(?:params|request\.(?:params|query)|@request)', "Reflected XSS: ERB/Rails raw output of request params", "CRITICAL"),
    (r'Response\.Write\s*\(\s*Request', "Reflected XSS: Response.Write with Request in ASP.NET", "CRITICAL"),
    (r'<\?=\s*\$_(?:_GET|_POST|_REQUEST)', "Reflected XSS: PHP short echo of user input", "CRITICAL"),

    # Stored XSS
    (r'\.innerHTML\s*=\s*.*\.(?:value|innerText|textContent)', "Stored XSS: innerHTML from stored content", "MEDIUM"),

    # Template Injection (SSTI)
    (r'render_template_string\s*\(', "SSTI: Flask render_template_string with user input", "CRITICAL"),
    (r'env\.from_string\s*\(', "SSTI: Jinja2 env.from_string with user input", "CRITICAL"),
    (r'Template\s*\(\s*.*\+', "SSTI: Go html/template with string concatenation", "HIGH"),
    (r'ERB\.new\s*\(', "SSTI: ERB.new with user input in Ruby", "CRITICAL"),
    (r'\{\s*\{\s*.*request\.', "SSTI: Django/Jinja2 template with request object", "MEDIUM"),

    # Python f-string / format HTML injection (Reflected XSS)
    (r'f[\"\']<\s*\w+[^\"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string HTML interpolation — user input in tag", "HIGH"),
    (r'[\"\']<[^\"\']*\{[^}]*\}[^\"\']*>[\"\']\s*\.format\s*\(', "Reflected XSS: .format() HTML interpolation", "HIGH"),
    (r'[\"\']<[^\"\']*%s[^\"\']*>[\"\']\s*%\s*', "Reflected XSS: %-formatting HTML interpolation", "MEDIUM"),
    (r'f[\"\']<\s*script[^\"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string script tag with variable", "CRITICAL"),

    # Template literals with user input (JS)
    (r'`<\w+[^`]*\$\{[a-zA-Z_]\w*\}', "Reflected XSS: template literal HTML with variable", "HIGH"),
]

HTML_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (r'v-html\s*=', "HTML Injection: Vue v-html directive — use v-text", "MEDIUM"),
    (r'ng-bind-html\s*=', "HTML Injection: Angular ng-bind-html", "MEDIUM"),
    (r'RichText|rich.?text|WYSIWYG', "Potential HTML Injection: rich text editor output", "INFO"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.erb',
                   '.html', '.htm', '.vue', '.svelte', '.go', '.java', '.cs',
                   '.aspx', '.jsp'}


def detect(ctx) -> list[dict]:
    findings = []
    files = _collect_files(ctx.path)
    for file_path in files:
        content = file_path.read_text(errors='replace')
        rel_path = str(file_path.relative_to(ctx.path))
        for pattern, message, severity in XSS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet, pattern):
                    continue
                context_start = max(0, line_no - 3)
                context_end = min(len(lines := content.split('\n')), line_no + 2)
                context = '\n'.join(lines[context_start:context_end])
                adjusted = _adjust_xss_severity(severity, pattern, context)
                findings.append({... "rule_id": "GS020", "severity": adjusted, ...})
        for pattern, message, severity in HTML_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                ...  # no FP filter, no severity adjustment
    return findings


def _is_false_positive(snippet: str, pattern: str) -> bool:
    snippet_lower = snippet.lower()
    if snippet.strip().startswith('//') or snippet.strip().startswith('#'):
        return True
    if snippet.strip().startswith('<!--'):
        return True
    if snippet.strip().startswith('/*') or snippet.strip().startswith('*'):
        return True
    if 'test' in snippet_lower or 'demo' in snippet_lower or 'example' in snippet_lower:
        if 'innerhtml' in pattern or 'document.write' in pattern:
            return True
    return False


_XSS_SANITIZERS = re.compile(
    r'(?:DOMPurify\.sanitize|escapeHtml|sanitizeHtml|encodeURIComponent|'
    r'html\.escape|bleach\.clean|xss-filters|\.textContent\s*=|'
    r'markupsafe\.escape|escape\s*\(|cgi\.escape|'
    r'jinja2\.escape|\{\{\s*\w+\s*\|\s*e(?:scape)?\s*\}\}|'
    r'esapi\.encoder|HtmlUtils\.htmlEscape)', re.IGNORECASE)

_XSS_TAINT_SOURCES = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE)|'
    r'input\s*\(|params\[|location\.(?:search|hash|href)|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:value|innerText|textContent)\b)', re.IGNORECASE)


def _has_xss_sanitizer(context: str) -> bool:
    return bool(_XSS_SANITIZERS.search(context))


def _has_tainted_source(context: str) -> bool:
    return bool(_XSS_TAINT_SOURCES.search(context))


def _adjust_xss_severity(severity: str, pattern: str, context: str) -> str:
    has_sanitizer = _has_xss_sanitizer(context)
    has_taint = _has_tainted_source(context)
    if has_sanitizer:
        return "LOW"
    if has_taint:
        if severity not in ("CRITICAL", "HIGH"):
            return "HIGH"
    return severity
```

## 4 зацепки (реальные, подтверждённые паттернами выше)

### Зацепка 1 — `.innerHTML =` static assignment (FP, HIGH)
Паттерн `\.innerHTML\s*=` матчит **любое** присваивание, включая статичное:
```js
el.innerHTML = '<div class="spinner">Loading…</div>';  // ← FP: нет user input
el.innerHTML = cachedHTML;                              // ← FP: кэш, не user input
```
Сейчас `_is_false_positive` не различает taint, а `_adjust_xss_severity` смотрит context ±3 строки — слабо.
**Решение**: если в строке нет taint source (`.value`, `location.search`, `request.`, `$_GET`, `${...}`) и нет переменной-интерполяции — это static assignment → FP. Требование: `el.innerHTML = userInput` должен остаться.

### Зацепка 2 — `eval()` / `setTimeout()` / `setInterval()` со статичной строкой (FP, CRITICAL/MEDIUM)
`eval\s*\(\s*[\"\'\`]` матчит статичный eval (bundler/minified):
```js
eval('use strict');               // ← FP: static, нет переменной
setTimeout('callback()', 100);    // ← FP: legacy string без переменной
```
**Решение**: если внутри кавычек нет `${}` / `{var}` / конкатенации / переменной — FP. `eval('alert(' + userInput + ')')` остаётся.

### Зацепка 3 — f-string / template literal HTML без user input (FP, HIGH)
`f'<div>{var}</div>'` и `` `<div>${var}</div>` `` матчатся как XSS, но `var` может быть внутренней (не user input):
```python
def render(user): return f'<div>{user.name}</div>'   # ← FP: user — ORM-объект, не request
```
**Решение**: taint-проверка на источник переменной (request/params/location/$_GET/`.value`). Без taint source — понизить/FP.

### Зацепка 4 — Java/JSP reflected XSS отсутствует (recall gap)
В `FILE_EXTENSIONS` есть `.jsp`, но нет паттерна для:
```jsp
<%= request.getParameter("name") %>          <!-- ← пропускается: reflected XSS -->
<c:out value="${param.name}" escapeXml="false" />  <!-- ← пропускается: явный bypass -->
```
**Решение**: добавить 1–2 JSP-паттерна (raw output + escapeXml="false"). Это поднимет recall на Java, не задев TP.

## Требования к ответу

Верни для каждой зацепки: тип фикса (`regex_сужение` | `context_analysis` | `новый_паттерн`), точный паттерн/код, пример FP/TP, влияние на recall, и regression-тест (синтетический input → ожидаемый finding/отсутствие).
Если зацепка режет recall — честно скажи и предложи безопасную альтернативу. Не выдумывай кейсы, которых нет в паттернах выше.
