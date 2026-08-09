# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""
GS005 — SQL/NoSQL Injection Patterns in Source Code.

Detects:
- String interpolation in SQL queries (f-strings, %, .format, + concat)
- UNION-based injection (SELECT ... UNION SELECT)
- Boolean-based blind (OR '1'='1, AND 1=1)
- Time-based blind (SLEEP, pg_sleep, WAITFOR DELAY, BENCHMARK)
- Stacked queries (multiple ;-separated statements)
- Second-order injection (DB fetch → unsanitized query)
- NoSQL injection (MongoDB $where/$regex, DynamoDB filter expressions)
- ORM anti-patterns (Django raw/extra/RawSQL, SQLAlchemy text/literal, Sequelize)
- Multi-language coverage: Python, Ruby, JS/TS, PHP, Java, Go, C#, Rust

Inspired by:
- OWASP A03:2021 — Injection
- PortSwigger SQL Injection Labs
- OWASP SQL Injection Prevention Cheat Sheet
"""

from __future__ import annotations

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS005"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "SQL/NoSQL injection: string interpolation in queries, UNION/Boolean/Time-based "
    "injection patterns, stacked queries, second-order, ORM anti-patterns"
)

# ── SQL keywords for context-aware filtering ──────────────────────────────

_SQL_KEYWORDS = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|MERGE|REPLACE|'
    r'UNION|JOIN|FROM|WHERE|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|OFFSET|'
    r'SET|VALUES|INTO|EXEC|EXECUTE|CALL)\b',
    re.IGNORECASE,
)

# ── User-input source patterns (for second-order / reachability) ──────────

_USER_INPUT_SOURCES = re.compile(
    r'\b(request\.(GET|POST|args|form|json|data|cookies|headers)|'
    r'params\[|req\.(query|body|params)|'
    r'\\$\_(GET|POST|REQUEST|COOKIE)|'
    r'input\s*\(|sys\.argv|os\.environ|'
    r'readline|scanf|cin\s*>>|'
    r'@RequestParam|@PathVariable|@RequestBody|'
    r'c\.QueryParam|c\.FormValue|c\.Param\()',
)

# ── SQL concatenation operators per language ──────────────────────────────

_SQL_CONCAT_OPS = re.compile(r'\|\||\s*\+\s*|\s*\.\s*')

# ── Pattern definitions ───────────────────────────────────────────────────
#
# Each pattern: (regex, title, language, extra_context_required)
# extra_context_required=True means the pattern only fires when user input
# source is present nearby (reduces false positives).

_PATTERNS: list[tuple[str, str, str, bool]] = [

    # ═══ PYTHON ═══════════════════════════════════════════════════════

    # --- String interpolation in execute() ---
    (r'(?:execute|cursor\.execute|conn\.execute|session\.execute)\s*\(\s*f["\']',
     "SQL f-string injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*%s.*%',
     "SQL %-formatting injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*\.format\(',
     "SQL .format() injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*["\']\s*\+\s*',
     "SQL string concatenation in execute()", "python", False),
    (r'\.executemany\s*\(\s*f["\']',
     "SQL f-string injection in executemany()", "python", False),

    # --- UNION-based injection ---
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*UNION\s+(?:ALL\s+)?SELECT',
     "UNION SELECT injection — data extraction via UNION", "python", False),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*SELECT.*FROM.*UNION.*SELECT',
     "UNION SELECT injection with multi-table", "python", False),

    # --- Boolean-based blind ---
    (r"(?:execute|cursor\.execute)\s*\(\s*f?[\"'].*(?:'\s*OR\s*'1'\s*=\s*'1|'\s*OR\s+1\s*=\s*1|AND\s+'1'\s*=\s*'2)",
     "Boolean-based blind SQLi ('OR '1'='1 / AND '1'='2)", "python", False),
    (r'(?:execute|cursor\.execute)\s*\(\s*f?["\'].*OR\s+\d+\s*=\s*\d+\s*--',
     "Boolean-based blind SQLi with numeric comparison", "python", False),

    # --- Time-based blind ---
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\b(SLEEP\s*\(|pg_sleep\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()',
     "Time-based blind SQLi (SLEEP/pg_sleep/WAITFOR/BENCHMARK)", "python", False),

    # --- Stacked queries ---
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)',
     "Stacked queries — multiple statements in one execute()", "python", False),

    # --- Django ORM ---
    (r'\.raw\s*\(\s*f["\']',
     "Django raw() with f-string — SQL injection", "python", False),
    (r'\.raw\s*\(\s*["\'].*%s.*%',
     "Django raw() with %-formatting", "python", False),
    (r'\.raw\s*\(\s*["\'].*\.format\(',
     "Django raw() with .format()", "python", False),
    (r'\.extra\s*\(\s*(?:select|where|tables)\s*=\s*f["\']',
     "Django extra() with f-string", "python", False),
    (r'\.extra\s*\(\s*(?:select|where|tables)\s*=\s*["\'].*\{',
     "Django extra() with .format()", "python", False),
    (r'RawSQL\s*\(\s*f["\']',
     "Django RawSQL with f-string", "python", False),
    (r'RawSQL\s*\(\s*["\'].*%',
     "Django RawSQL with %-formatting", "python", False),
    (r'(?:\.annotate|\.alias)\s*\(\s*\w+\s*=\s*RawSQL\s*\(',
     "Django annotate() with RawSQL", "python", False),

    # --- SQLAlchemy ---
    (r'text\s*\(\s*f["\']',
     "SQLAlchemy text() with f-string", "python", False),
    (r'text\s*\(\s*["\'].*%.*["\']\s*%',
     "SQLAlchemy text() with %-formatting", "python", False),
    (r'text\s*\(\s*["\'].*["\']\s*\+\s*',
     "SQLAlchemy text() with string concatenation", "python", False),
    (r'\.literal\s*\(\s*request\.',
     "SQLAlchemy literal() with request data — injection", "python", False),
    (r'(?:conn|engine)\.execute\s*\(\s*text\s*\(\s*f["\']',
     "SQLAlchemy engine.execute(text(f\"...\"))", "python", False),

    # --- Flask-SQLAlchemy ---
    (r'db\.(?:session|engine)\.execute\s*\(\s*f["\']',
     "Flask-SQLAlchemy execute() with f-string", "python", False),
    (r'db\.(?:session|engine)\.execute\s*\(\s*["\'].*\{',
     "Flask-SQLAlchemy execute() with .format()", "python", False),

    # --- Second-order SQLi ---
    # Two orders: (A) row extraction BEFORE execute (two-step), (B) row INSIDE execute(f"...") inline
    (r'(?:row\[|row\.|record\[|record\.|result\[)\s*["\']?\w+["\']?\s*\].*'
     r'(?:execute|cursor\.execute)\s*\(\s*f["\']',
     "Second-order SQLi — DB data used unsanitized in f-string query", "python", True),
    (r'(?:execute|cursor\.execute)\s*\(\s*f["\'].*'
     r'(?:row\[|row\.|record\[|record\.|result\[)\s*["\']?\w+["\']?\s*\]',
     "Second-order SQLi — inline DB data in f-string query", "python", True),
    (r'(?:row\[|row\.|record\[)\s*["\']?\w+["\']?\s*\].*'
     r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%',
     "Second-order SQLi — DB data used unsanitized in %-formatted query", "python", True),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%.*'
     r'(?:row\[|row\.|record\[)\s*["\']?\w+["\']?\s*\]',
     "Second-order SQLi — inline DB data in %-formatted query", "python", True),

    # ═══ RUBY ════════════════════════════════════════════════════════════

    (r'\.where\s*\(\s*["\']\$\{',
     "Rails where() with interpolation", "ruby", False),
    (r'\.where\s*\(\s*["\'].*#\{',
     "Rails where() with string interpolation", "ruby", False),
    (r'\.find_by_sql\s*\(\s*["\']\$\{',
     "Rails find_by_sql injection", "ruby", False),
    (r'\.find_by_sql\s*\(\s*["\'].*#\{',
     "Rails find_by_sql with interpolation", "ruby", False),
    (r'ActiveRecord::Base\.connection\.execute\s*\(\s*["\'].*#\{',
     "ActiveRecord connection.execute with interpolation", "ruby", False),
    (r'\.select_all\s*\(\s*["\'].*#\{',
     "Rails select_all with interpolation", "ruby", False),

    # ═══ JavaScript / TypeScript ═════════════════════════════════════════

    (r'\.query\s*\(\s*`\$\{',
     "Node.js template literal SQL injection (query)", "javascript", False),
    (r'\.execute\s*\(\s*`\$\{',
     "Node.js template literal SQL injection (execute)", "javascript", False),
    (r'(?:pool|connection|db)\.(?:query|execute)\s*\(\s*["\'].*["\']\s*\+\s*',
     "Node.js string concat in SQL query", "javascript", False),
    (r'(?:pool|connection|db)\.(?:query|execute)\s*\(\s*["\'].*\$\{',
     "Node.js template literal in query string", "javascript", False),

    # --- Sequelize ---
    (r'sequelize\.query\s*\(\s*`\$\{',
     "Sequelize raw query with template literal", "javascript", False),
    (r'sequelize\.query\s*\(\s*["\'].*["\']\s*\+\s*',
     "Sequelize raw query with string concat", "javascript", False),
    (r'\.findAll\s*\(\s*\{\s*where\s*:\s*`\$\{',
     "Sequelize findAll with template literal in where", "javascript", False),

    # --- Knex ---
    (r'knex\.raw\s*\(\s*`\$\{',
     "Knex raw() with template literal", "javascript", False),
    (r'knex\.raw\s*\(\s*["\'].*["\']\s*\+\s*',
     "Knex raw() with string concat", "javascript", False),

    # ═══ PHP ═════════════════════════════════════════════════════════════

    (r'mysql_query\s*\(\s*["\']\$\w+',
     "PHP mysql_query injection", "php", False),
    (r'mysqli_query\s*\(\s*\$\w+\s*\.',
     "PHP mysqli_query with concat", "php", False),
    (r'mysqli_query\s*\(\s*\$\w+\s*,\s*["\'].*["\']\s*\.',
     "PHP mysqli_query with string concat", "php", False),
    (r'(?:PDO|pdo)->(?:query|exec)\s*\(\s*["\'].*["\']\s*\.',
     "PHP PDO query() with string concat", "php", False),
    (r'(?:PDO|pdo)->(?:query|exec)\s*\(\s*["\'].*\{\$',
     "PHP PDO query() with variable interpolation", "php", False),
    (r'pg_query\s*\(\s*\$\w+\s*,\s*["\'].*["\']\s*\.',
     "PHP pg_query with concat", "php", False),

    # --- Laravel Eloquent ---
    (r'DB::(?:select|statement|raw)\s*\(\s*["\'].*["\']\s*\.',
     "Laravel DB::raw() with concat", "php", False),
    (r'DB::(?:select|statement)\s*\(\s*["\'].*\{\$',
     "Laravel DB::select() with variable interpolation", "php", False),
    (r'->whereRaw\s*\(\s*["\'].*\{\$',
     "Laravel whereRaw() with variable interpolation", "php", False),

    # ═══ JAVA ════════════════════════════════════════════════════════════

    (r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)?\s*\(\s*["\'].*["\']\s*\+\s*',
     "Java JDBC Statement with string concat", "java", False),
    (r'String\s+\w+\s*=\s*["\']SELECT.*["\']\s*\+\s*\w+',
     "Java SQL query built with string concatenation", "java", False),
    (r'(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|update)\s*\(\s*["\'].*["\']\s*\+\s*',
     "Spring JDBC template with string concat", "java", False),
    (r'\.createQuery\s*\(\s*["\'].*["\']\s*\+\s*',
     "JPA/Hibernate createQuery with string concat", "java", False),

    # ═══ GO ═════════════════════════════════════════════════════════════

    (r'db\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|".*"\s*\+\s*)',
     "Go database/sql with fmt.Sprintf or string concat", "go", False),
    (r'fmt\.Sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "Go fmt.Sprintf building SQL query", "go", False),

    # ═══ C# ═════════════════════════════════════════════════════════════

    (r'new\s+SqlCommand\s*\(\s*["\'].*["\']\s*\+\s*',
     "C# SqlCommand with string concat", "csharp", False),
    (r'\.Execute(?:Reader|Scalar|NonQuery)\s*\(\s*\)',
     "C# SqlCommand with string concat", "csharp", False),  # caught by the one above, kept for framework coverage
    (r'string\.Format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "C# string.Format building SQL query", "csharp", False),
    (r'\$@"(?:SELECT|INSERT|UPDATE|DELETE).*\{',
     "C# interpolated string in SQL query", "csharp", False),

    # ═══ NoSQL Injection ═════════════════════════════════════════════════

    # MongoDB
    (r'\$where\s*:\s*(?:f["\']|`\$\{)',
     "MongoDB $where with string interpolation — NoSQL injection", "javascript", False),
    (r'\$regex\s*:\s*(?:request\.|req\.|params\[)',
     "MongoDB $regex from user input — ReDoS / NoSQL injection", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$where\s*:',
     "MongoDB find() with $where — arbitrary JS execution", "javascript", False),
    (r'(?:collection|db)\.(?:find|aggregate)\s*\(\s*\{[^}]*\$\{',
     "MongoDB query with template literal — NoSQL injection", "javascript", False),

    # DynamoDB
    (r'FilterExpression\s*=\s*f["\']',
     "DynamoDB FilterExpression with f-string — NoSQL injection", "python", False),
    (r'KeyConditionExpression\s*=\s*f["\']',
     "DynamoDB KeyConditionExpression with f-string", "python", False),

    # Redis
    (r'(?:redis|r)\.(?:execute_command|eval)\s*\(\s*f["\']',
     "Redis execute_command/eval with f-string — command injection", "python", False),

    # ═══ ORM / Query Builder Anti-patterns ═══════════════════════════════

    # Generic — execute() with template literal
    (r'\.execute\s*\(\s*["\'].*\$\{.*\}.*["\']',
     "Template literal in SQL execute", "generic", False),

    # Pandas read_sql with f-string
    (r'pd\.read_sql(?:query)?\s*\(\s*f["\']',
     "Pandas read_sql with f-string", "python", False),
    (r'pd\.read_sql(?:query)?\s*\(\s*["\'].*\{',
     "Pandas read_sql with .format()", "python", False),

    # Rust sqlx::query with format!
    (r'sqlx::query\s*\(\s*format!',
     "Rust sqlx::query with format!()", "rust", False),
    (r'sqlx::query_as\s*\(\s*format!',
     "Rust sqlx::query_as with format!()", "rust", False),
]

# ── Per-language file extensions ──────────────────────────────────────────

_LANG_EXTS: dict[str, tuple[str, ...] | None] = {
    "python": (".py", ".pyi", ".pyx"),
    "ruby": (".rb", ".erb"),
    "javascript": (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "php": (".php", ".phtml", ".php3", ".php4", ".php5", ".inc"),
    "java": (".java", ".jsp", ".jspx"),
    "go": (".go",),
    "csharp": (".cs", ".razor", ".cshtml"),
    "rust": (".rs",),
    "generic": None,  # all extensions
}


def _has_user_input_nearby(content: str, match_end: int, window: int = 500) -> bool:
    """Check if user-input source exists within `window` chars after the match."""
    after = content[match_end:match_end + window]
    return bool(_USER_INPUT_SOURCES.search(after))


def _count_sql_keywords(line: str) -> int:
    """Count SQL keywords in a line — for filtering noise."""
    return len(_SQL_KEYWORDS.findall(line))


def _detect_line(
    line: str,
    filename: str,
    filepath: Path,
) -> list[Finding]:
    """Detect SQLi patterns in a single line. Returns list of Findings."""
    findings: list[Finding] = []

    for pattern, title, lang, needs_context in _PATTERNS:
        exts = _LANG_EXTS.get(lang)
        if exts is not None and filepath.suffix not in exts:
            continue

        for m in re.finditer(pattern, line, re.IGNORECASE):
            matched_text = m.group(0)

            # ── Skip safe patterns ──────────────────────────────
            if "gsc:ignore" in line or "nosec" in line:
                continue
            if "PRAGMA" in line.upper():
                continue
            if "reply_text" in line:
                continue

            # Skip text() without SQL keywords (likely not SQLAlchemy)
            if "text(" in matched_text and "text(" in line and not _SQL_KEYWORDS.search(line):
                continue

            # Skip purely literal strings in list/dict without any user input signs
            if not needs_context and _count_sql_keywords(line) == 0:
                # No SQL keywords AND no user input markers → likely not SQL
                if not re.search(r'[%{}]|\$\{|\+.*SELECT|f["\']', line):
                    continue

            # Skip parameterized queries (placeholder detected)
            if re.search(r'%s\s*,\s*\(|%s\s*,\s*\[|\?\s*,\s*\[', line):
                continue

            # ── Build finding ──────────────────────────────────

            fix = (
                "Use parameterized queries / prepared statements. "
                "Python: cursor.execute('SELECT ...', (param,)). "
                "JavaScript: pool.query('SELECT ...', [param]). "
                "Java: PreparedStatement. "
                "Go: db.Query('SELECT ...', param). "
                "PHP: PDO::prepare() + bindParam()."
            )

            severity = "CRITICAL"
            if "NoSQL" in title or "read_sql" in title:
                severity = "HIGH"
            if "format!" in matched_text:
                severity = "HIGH"

            findings.append(Finding(
                rule_id=RULE_ID,
                severity=severity,
                title=title,
                file_path=str(filepath),
                line_number=0,  # filled after by caller
                detail=f"{matched_text[:140]}",
                fix_suggestion=fix,
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/sql-injection",
                ],
            ))

    return findings


# ── Sanitizer detection for f-string SQL downgrade ────────────────────────

_SANITIZER_PATTERNS = re.compile(
    r'\b(?:ident|scrub|escape_identifier|quote_ident|_sqlite_ident|sanitize)'
    r'|\.replace\(["\']\\[\'"]["\'],\s*["\']\\1["\']\)'
    r'|_safe_\w+',
    re.IGNORECASE,
)


def _has_sanitizer(context: str) -> bool:
    """Check if surrounding context contains identifier sanitizer calls."""
    return bool(_SANITIZER_PATTERNS.search(context))


# ── Taint source detection for SQL injection ──────────────────────────────

_TAINT_SOURCE_PATTERNS = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data)\s*\()',
    re.IGNORECASE,
)


def _has_taint_source(context: str) -> bool:
    """Check if SQL query variables come from user input."""
    return bool(_TAINT_SOURCE_PATTERNS.search(context))


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect SQL/NoSQL injection patterns in source code."""
    if RULE_ID in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []

    for fp in ctx.get_source_files():
        try:
            content = ctx.read_file(fp)
        except Exception:
            continue

        lines = content.split("\n")
        for lineno, line in enumerate(lines, 1):
            if not line.strip() or line.strip().startswith("#"):
                continue

            line_findings = _detect_line(line, fp.name, fp)
            for f in line_findings:
                f["line_number"] = lineno
                f["line"] = lineno
                f["detail"] = f"Line {lineno}: {line.strip()[:140]}"
                # Downgrade f-string SQL if sanitizer present in context
                if f.get("severity") == "CRITICAL" and "f-string" in f.get("title", ""):
                    context = "\n".join(lines[max(0, lineno-3):lineno])
                    has_san = _has_sanitizer(context)
                    has_taint = _has_taint_source(context)
                    if has_san:
                        f["severity"] = "LOW"
                        f["title"] = f["title"] + " [sanitized — verify manually]"
                    elif not has_taint:
                        # No taint source — hardcoded values, low exploitability
                        f["severity"] = "MEDIUM"
                        f["title"] = f["title"] + " [no user input — verify]"
                findings.append(f)

    return findings
