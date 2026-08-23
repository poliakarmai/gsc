# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GS005 — SQL/NoSQL Injection Detector (v2.0: pattern_id decomposition).

75 patterns across 9 languages. Each pattern has a unique pattern_id.
Per-pattern precision can be tracked and noisy patterns selectively disabled.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Finding
from .base import make_finding

# ── assign_ids (inlined for module-relative import) ────────────────────────

import re as _re

_TYPE_MAP = {
    "f-string": "FSTR", "format(": "FMT", "%.format": "FMT",
    "concat": "CONCAT", "$where": "NOSQL", "MongoDB": "NOSQL",
    "DynamoDB": "NOSQL", "Redis": "NOSQL",
    "Django": "ORM", "SQLAlchemy": "ORM", "Sequelize": "ORM",
    "Knex": "ORM", "Laravel": "ORM", "ActiveRecord": "ORM",
    "createQuery": "ORM", "JDBC": "JDBC", "Statement": "JDBC",
    "JPA": "JDBC", "Spring": "JDBC", "SqlCommand": "CSHARP",
}
_LANG_CODE = {"python": "PY", "javascript": "JS", "ruby": "RB",
              "php": "PHP", "java": "JAVA", "go": "GO",
              "csharp": "CS", "rust": "RS", "generic": "GEN"}


def _assign_ids(patterns):
    counters = {}
    result = []
    for regex, title, lang, needs_ctx in patterns:
        ptype = "GEN"
        for key, code in _TYPE_MAP.items():
            if key.lower() in title.lower():
                ptype = code; break
        lcode = _LANG_CODE.get(lang, "X")
        counters[(ptype, lcode)] = counters.get((ptype, lcode), 0) + 1
        pid = f"GS005-{ptype}-{lcode}-{counters[(ptype, lcode)]:03d}"
        result.append((pid, regex, title, lang, needs_ctx))
    return result

RULE_ID = "GS005"
ECHELON = 2
NOISE_TIER = "precise"
description = "GS005: SQL/NoSQL injection — 75 patterns, 9 languages, per-pattern precision tracking (v2.0)"

# ── User input sources for context filtering ───────────────────────────────

_USER_INPUT_SOURCES = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE|headers)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data|params)\s*\()',
    re.IGNORECASE,
)

_SQL_KEYWORDS = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|FROM|WHERE|'
    r'JOIN|INTO|SET|VALUES|TABLE|UNION|ORDER\s+BY|GROUP\s+BY|'
    r'HAVING|LIMIT|OFFSET|EXEC|EXECUTE)\b',
    re.IGNORECASE,
)


# ── Language extension map ─────────────────────────────────────────────────

_LANG_EXTS: dict[str, tuple[str, ...] | None] = {
    "python": (".py", ".pyi", ".pyx"),
    "javascript": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "ruby": (".rb", ".erb"),
    "php": (".php", ".phtml", ".php3", ".php4", ".php5"),
    "java": (".java", ".jsp", ".jspx"),
    "go": (".go",),
    "csharp": (".cs", ".razor", ".cshtml"),
    "rust": (".rs",),
    "generic": None,
}


# ── _PATTERNS (raw, without pattern_ids) ───────────────────────────────────

_RAW_PATTERNS: list[tuple[str, str, str, bool]] = [

    # ═══ PYTHON ═══════════════════════════════════════════════════════

    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*f["\']',
     "SQL f-string injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%',
     "SQL %-formatting injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*\{.*\}.*["\']\s*\.format\s*\(',
     "SQL .format() injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*["\']\s*\+\s*(?!\s*["\'])',
     "SQL string concatenation in execute()", "python", False),
    (r'executemany\s*\(\s*f["\']',
     "SQL f-string injection in executemany()", "python", False),

    # Boolean/Time blind SQLi
    (r'\b(?:UNION)\s+SELECT\b', "UNION SELECT injection", "python", False),
    (r"(?:UNION)\s+(?:ALL\s+)?SELECT\s+.*SELECT",
     "UNION SELECT injection with multi-table", "python", False),
    (r'\bOR\s+[\'"]\d[\'"]\s*=\s*[\'"]\d[\'"]\b', "Boolean-based blind SQLi", "python", False),
    (r'\bAND\s+[\'"]\d[\'"]\s*=\s*[\'"]\d[\'"]\b', "Boolean-based blind SQLi numeric", "python", False),
    (r'(?<![\w.])(?:SLEEP|pg_sleep|WAITFOR\s+DELAY|BENCHMARK)\s*\(', "Time-based blind SQLi", "python", False),

    # Stacked queries
    (r';\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b', "Stacked query injection", "python", False),

    # Django ORM
    (r'\.raw\s*\(\s*f["\']', "Django raw() with f-string", "python", False),
    (r'\.raw\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%', "Django raw() with %-formatting", "python", False),
    (r'\.extra\s*\(\s*where\s*=\s*["\'].*["\']\s*[\+%]', "Django extra() with dynamic WHERE", "python", False),
    (r'\.extra\s*\(\s*tables\s*=\s*\[.*["\']\s*\+', "Django extra() with dynamic tables", "python", False),
    (r'cursor\.execute\s*\(\s*.*SELECT.*\{.*\}.*FROM', "Django cursor.execute() with interpolation", "python", False),
    (r'\.annotate\s*\(\s*.*RawSQL\s*\(', "Django RawSQL annotation injection", "python", False),
    (r'\.annotate\s*\(\s*.*Func\s*\(\s*.*Value\s*\(', "Django Func+Value expression injection", "python", False),
    (r'\.filter\s*\(\s*.*__\w+\s*=\s*.*\+', "Django filter() with string concat", "python", False),

    # SQLAlchemy
    (r'text\s*\(\s*f["\']', "SQLAlchemy text() with f-string", "python", False),
    (r'text\s*\(\s*["\'].*\{.*\}.*["\']\s*\.format\s*\(', "SQLAlchemy text() with .format()", "python", False),
    (r'text\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%', "SQLAlchemy text() with %-formatting", "python", False),
    (r'text\s*\(\s*["\'].*["\']\s*\+', "SQLAlchemy text() with string concat", "python", False),
    (r'\.from_statement\s*\(\s*text\s*\(', "SQLAlchemy from_statement(text())", "python", False),
    (r'session\.execute\s*\(\s*text\s*\(\s*f["\']', "SQLAlchemy session.execute(text(f))", "python", False),

    # Flask-SQLAlchemy
    (r'db\.engine\.execute\s*\(\s*f["\']', "Flask-SQLAlchemy f-string SQL", "python", False),
    (r'db\.session\.execute\s*\(\s*text\s*\(\s*f["\']', "Flask-SQLAlchemy text(f)", "python", False),

    # Second-order SQLi
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*FROM\s+\w+\s+WHERE.*\[.*\]', "Second-order SQLi from stored data", "python", False),
    # Deactivated (20.08.2026): "execute with <collection>[idx]" patterns are
    # dict/list/attribute access — passing a value into execute(), NOT SQLi.
    # 3/3 revalidated FP, 0 TP. The real SQLi case (interpolation around the
    # access) is already caught by the dedicated f-string/format patterns above.

    # Pandas
    (r'read_sql_query\s*\(\s*f["\']', "Pandas read_sql_query with f-string", "python", False),
    (r'read_sql\s*\(\s*f["\']', "Pandas read_sql with f-string", "python", False),

    # Two-step SQLi: query built by interpolation/concat in a SEPARATE statement
    # from execute()/raw(). e.g. vuln-flask `str_query = "...%s..." % term`,
    # pygoat `sql_query = "SELECT..." + name + ...` then `login.objects.raw(...)`.
    # needs_ctx=True → require a taint source in nearby context (see detect()).
    (r'["\'](?:SELECT|INSERT|UPDATE|DELETE).*%[sd]\b.*["\']\s*%',
     "SQL %-formatting query building", "python", True),
    (r'["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*(?!\s*["\'])',
     "SQL string concat query building", "python", True),

    # ═══ JAVASCRIPT / TYPESCRIPT ═══════════════════════════════════════

    (r'\.(?:query|execute)\s*\(\s*`.*\$\{.*\}.*`', "Template literal SQL injection", "javascript", False),
    (r'\.(?:query|execute)\s*\(\s*[\"\'].*[\"\']\s*\+\s*', "String concat SQL injection", "javascript", False),
    (r'\.query\s*\(\s*.*SELECT.*\+', "query() with string concat", "javascript", False),
    (r'\.execute\s*\(\s*.*INSERT.*\+', "execute() with INSERT concat", "javascript", False),

    # Sequelize
    (r'sequelize\.query\s*\(\s*.*\$\{', "Sequelize query() with template literal", "javascript", False),
    (r'\.findAll\s*\(\s*\{.*where.*:\s*.*\$\{', "Sequelize findAll with dynamic where", "javascript", False),
    (r'\.query\s*\(\s*.*replacements.*\$\{', "Sequelize replacements injection", "javascript", False),

    # Knex
    (r'knex\.raw\s*\(\s*`.*\$\{', "Knex raw() with template literal", "javascript", False),
    (r'knex\s*\(.*\)\.whereRaw\s*\(', "Knex whereRaw() injection", "javascript", False),

    # MongoDB (NoSQL injection)
    (r'\$where\s*:\s*(?:f["\']|`\$\{)', "MongoDB $where with interpolation", "javascript", False),
    (r'\$regex\s*:\s*(?:request\.|req\.|params\[)', "MongoDB $regex from user input", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$where\s*:', "MongoDB find() with $where", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$expr\s*:', "MongoDB find() with $expr injection", "javascript", False),

    # ═══ PHP ═══════════════════════════════════════════════════════════

    (r'mysql_query\s*\(\s*["\'].*["\']\s*\.', "PHP mysql_query with concat", "php", False),
    (r'mysqli_query\s*\(\s*.*["\']\s*\.', "PHP mysqli_query with concat", "php", False),
    (r'mysqli::query\s*\(\s*.*["\']\s*\.', "PHP mysqli::query with concat", "php", False),
    (r'PDO::query\s*\(\s*["\'].*["\']\s*\.', "PHP PDO::query with concat", "php", False),
    (r'->prepare\s*\(\s*["\'].*["\']\s*\.', "PHP prepare() with concat", "php", False),
    (r'DB::select\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::select with concat", "php", False),
    (r'DB::raw\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::raw with concat", "php", False),
    (r'DB::statement\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::statement with concat", "php", False),
    (r'pg_query\s*\(\s*.*["\']\s*\.', "PHP pg_query with concat", "php", False),

    # ═══ RUBY ══════════════════════════════════════════════════════════

    (r'\.(?:find_by_sql|find_by_sql)\s*\(\s*["\'].*#\{', "Rails find_by_sql with interpolation", "ruby", False),
    (r'\.where\s*\(\s*["\'].*#\{', "Rails where() with string interpolation", "ruby", False),
    (r'ActiveRecord::Base\.connection\.execute\s*\(\s*["\'].*#\{', "Rails execute() with interpolation", "ruby", False),
    (r'\.(?:select_all|select_rows)\s*\(\s*["\'].*#\{', "Rails select_all with interpolation", "ruby", False),
    (r'\.update_all\s*\(\s*["\'].*#\{', "Rails update_all with interpolation", "ruby", False),
    (r'\.delete_all\s*\(\s*["\'].*#\{', "Rails delete_all with interpolation", "ruby", False),

    # ═══ JAVA ════════════════════════════════════════════════════════════

    (r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)?\s*\(\s*["\'].*["\']\s*\+\s*',
     "Java JDBC Statement with string concat", "java", False),
    (r'String\s+\w+\s*=\s*["\']SELECT.*["\']\s*\+\s*\w+',
     "Java SQL query built with string concatenation", "java", False),
    (r'(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|update)\s*\(\s*["\'].*["\']\s*\+\s*',
     "Spring JDBC template with string concat", "java", False),
    (r'\.createQuery\s*\(\s*["\'].*["\']\s*\+\s*',
     "JPA/Hibernate createQuery with string concat", "java", False),
    (r'String\s+\w+\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*\w+',
     "Java SQL built with string concat (INSERT/UPDATE/DELETE)", "java", False),
    (r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)\s*\(\s*\w+\s*\)',
     "Java JDBC executeQuery/executeUpdate with SQL variable", "java", False),

    # ═══ GO ═════════════════════════════════════════════════════════════

    (r'db\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|".*"\s*\+\s*)',
     "Go database/sql with fmt.Sprintf or string concat", "go", False),
    (r'fmt\.Sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "Go fmt.Sprintf building SQL query", "go", False),

    # ═══ C# ═════════════════════════════════════════════════════════════

    (r'new\s+SqlCommand\s*\(\s*["\'].*["\']\s*\+\s*',
     "C# SqlCommand with string concat", "csharp", False),
    (r'\.Execute(?:Reader|Scalar|NonQuery)\s*\(\s*\)',
     "C# SqlCommand with string concat", "csharp", False),
    (r'string\.Format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "C# string.Format building SQL query", "csharp", False),

    # ═══ RUST ═══════════════════════════════════════════════════════════

    (r'sqlx::query\s*\(\s*["\'].*["\']\s*\+\s*',
     "Rust sqlx::query with string concat", "rust", False),
    (r'sqlx::query_as\s*\(\s*["\'].*["\']\s*\+\s*',
     "Rust sqlx::query_as with string concat", "rust", False),

    # ═══ NoSQL Injection ═══════════════════════════════════════════════

    (r'\$where\s*:\s*(?:f["\']|`\$\{)',
     "MongoDB $where with string interpolation — NoSQL injection", "javascript", False),
    (r'\$regex\s*:\s*(?:request\.|req\.|params\[)',
     "MongoDB $regex from user input — ReDoS / NoSQL injection", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$where\s*:',
     "MongoDB find() with $where — NoSQL injection", "javascript", False),
    (r'\.find_one_and_update\s*\(\s*\{\s*\$set\s*:',
     "MongoDB find_one_and_update with $set injection", "javascript", False),
]


# ── Build _PATTERNS with pattern_ids (deterministic) ───────────────────────

_PATTERNS: list[tuple[str, str, str, str, bool]] = _assign_ids(_RAW_PATTERNS)
# Format: (pattern_id, regex, title, language, extra_context_required)


# ── Sanitizer detection ────────────────────────────────────────────────────

_SANITIZER_PATTERNS = re.compile(
    r'\b(?:ident|scrub|escape_identifier|quote_ident|_sqlite_ident|sanitize)'
    r'|\.replace\([\"\']\\[\'\"][\"\'],\s*[\"\']\\1[\"\']\)'
    r'|_safe_\w+',
    re.IGNORECASE,
)

_TAINT_SOURCE_PATTERNS = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data|params)\s*\()',
    re.IGNORECASE,
)


# Patterns that only represent SQLi when the query is *built by interpolation*.
# A bare `execute(<collection>[idx])` (prebuilt query) or a hardcoded `IN [...]`
# list inside a static query is NOT injection — skip when no interpolation is present.
_INTERPOLATION_REQUIRED = {
    "GS005-GEN-PY-008",  # Second-order SQLi from stored data
}

_REAL_INTERPOLATION = re.compile(
    r'f["\']|\.format\s*\(|["\']\s*%|\+\s*(?!\s*["\'])',
)


def _has_sanitizer(context: str) -> bool:
    return bool(_SANITIZER_PATTERNS.search(context))


def _has_taint_source(context: str) -> bool:
    return bool(_TAINT_SOURCE_PATTERNS.search(context))


def _get_disabled(ctx: AuditContext) -> set[str]:
    """Get disabled pattern IDs from AuditContext (cached per scan)."""
    try:
        return ctx.get_disabled_patterns(RULE_ID)
    except (AttributeError, Exception):
        return set()


# ── Core detection ─────────────────────────────────────────────────────────

def detect(ctx: AuditContext) -> list[Finding]:
    """Detect SQL/NoSQL injection patterns with per-pattern tracking.

    v2.0: pattern_ids in metadata, location-based dedup, disabled patterns.
    """
    if RULE_ID in ctx.skipped_detectors:
        return []

    disabled = _get_disabled(ctx)
    findings: list[Finding] = []

    for fp in ctx.get_source_files():
        # Skip DB migrations (Alembic/Flyway) — SQL there is DDL/DML on
        # constants, not user-facing query construction.
        if "migration" in fp.as_posix().lower():
            continue
        try:
            content = ctx.read_file(fp)
        except Exception:
            continue

        lines = content.split("\n")

        # Group matches by (line, snippet) → one finding per location
        locations: dict[tuple[int, str], dict] = {}

        for pid, regex, title, lang, needs_context in _PATTERNS:
            if pid in disabled:
                continue

            exts = _LANG_EXTS.get(lang)
            if exts is not None and fp.suffix not in exts:
                continue

            for m in re.finditer(regex, content, re.IGNORECASE):
                matched = m.group(0)
                line_no = content[:m.start()].count("\n") + 1
                snippet = matched[:200]
                line = lines[line_no - 1] if line_no <= len(lines) else ""

                # Safety filters (preserved from v1)
                if "gsc:ignore" in line or "nosec" in line:
                    continue
                if "PRAGMA" in line.upper():
                    continue
                if "reply_text" in line:
                    continue
                if "text(" in matched and "text(" in line and not _SQL_KEYWORDS.search(line):
                    continue
                if not needs_context and len(_SQL_KEYWORDS.findall(line)) == 0:
                    if not re.search(r'[%{}]|\$\{|\\+.*SELECT|f["\']', line):
                        continue
                if re.search(r'(\?|%s)', line) and re.search(r'\.join\s*\(', line):
                    continue
                if re.search(r'(?:%[sd]|\?|:\w+)\s*["\']\s*,\s*[\[({]', line):
                    continue
                if pid in _INTERPOLATION_REQUIRED and not _REAL_INTERPOLATION.search(line):
                    continue
                if needs_context:
                    _ctx = "\n".join(lines[max(0, line_no - 150):line_no + 1])
                    if not _has_taint_source(_ctx):
                        continue

                key = (line_no, snippet)
                if key not in locations:
                    locations[key] = {"title": title, "pattern_ids": [],
                                      "lang": lang, "line": line}
                locations[key]["pattern_ids"].append(pid)

        # Build findings from grouped locations
        for (line_no, snippet), data in locations.items():
            severity = "CRITICAL"
            if "NoSQL" in data["title"] or "read_sql" in data["title"]:
                severity = "HIGH"
            if "format!" in data["title"]:
                severity = "HIGH"

            f = make_finding(
                rule_id=RULE_ID,
                title=data["title"],
                severity=severity,
                confidence=0.85,
                file=str(fp),
                line=line_no,
                snippet=snippet,
                metadata={
                    "pattern_ids": data["pattern_ids"],
                    "language": data["lang"],
                },
            )
            if f is None:
                continue

            # Downgrade f-string SQL if sanitizer or no taint source
            if f["severity"] == "CRITICAL" and "f-string" in f["title"]:
                context = "\n".join(lines[max(0, line_no - 3):line_no])
                if _has_sanitizer(context):
                    f["severity"] = "LOW"
                    f["title"] = f["title"] + " [sanitized — verify manually]"
                elif not _has_taint_source(context):
                    f["severity"] = "MEDIUM"
                    f["title"] = f["title"] + " [no user input — verify]"

            findings.append(f)

    return findings
