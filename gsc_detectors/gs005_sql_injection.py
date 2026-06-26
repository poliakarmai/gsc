"""
GS005 — SQL injection patterns in source code.

Detects:
- String interpolation in SQL queries (f-strings, %, .format)
- Raw SQL with user-controlled input
- Missing parameterized queries
- Dangerous ORM raw/execute patterns

Inspired by OWASP A03:2021 — Injection.
"""

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS005"
ECHELON = 2

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, title, language)

    # Python f-string SQL
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*f["\']', "SQL f-string injection", "python"),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s.*%.*["\']', "SQL %-formatting injection", "python"),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\.format\(.*["\']', "SQL .format() injection", "python"),
    # Raw SQL with +
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*["\']\s*\+\s*', "SQL string concatenation injection", "python"),

    # Django ORM raw/extra
    (r'\.raw\s*\(\s*f["\']', "Django raw() with f-string — SQL injection", "python"),
    (r'\.raw\s*\(\s*["\'].*%s.*%.*["\']', "Django raw() with %-formatting", "python"),
    (r'\.extra\s*\(\s*where\s*=\s*f["\']', "Django extra() with f-string", "python"),
    (r'RawSQL\s*\(\s*f["\']', "Django RawSQL with f-string", "python"),

    # SQLAlchemy text() with interpolation
    (r'text\s*\(\s*f["\']', "SQLAlchemy text() with f-string", "python"),
    (r'text\s*\(\s*["\'].*%.*["\']\s*%', "SQLAlchemy text() with %-formatting", "python"),

    # Ruby on Rails
    (r'\.where\s*\(\s*["\']\$\{', "Rails where() with interpolation", "ruby"),
    (r'\.find_by_sql\s*\(\s*["\']\$\{', "Rails find_by_sql injection", "ruby"),

    # JavaScript/TypeScript
    (r'\.query\s*\(\s*`\$\{', "Node.js template literal SQL injection", "javascript"),
    (r'\.execute\s*\(\s*`\$\{', "Node.js execute with template literal", "javascript"),

    # PHP
    (r'mysql_query\s*\(\s*["\']\$\w+', "PHP mysql_query injection", "php"),
    (r'mysqli_query\s*\(\s*\$\w+\s*\.', "PHP mysqli_query with concat", "php"),

    # Generic — query builder without params
    (r'\.execute\s*\(\s*["\'].*\$\{.*\}.*["\']', "Template literal in SQL execute", "generic"),
]

# Per-language file extensions
_LANG_EXTS = {
    "python": (".py",),
    "ruby": (".rb",),
    "javascript": (".js", ".ts", ".jsx", ".tsx"),
    "php": (".php",),
    "generic": None,  # all extensions
}


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect SQL injection patterns in source code."""
    if "GS005" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for pattern, title, lang in _PATTERNS:
        exts = _LANG_EXTS.get(lang)
        files = ctx.get_source_files(extensions=exts) if exts else ctx.get_source_files()
        for fp in files:
            content = ctx.read_file(fp)
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue
                # Skip PRAGMA (safe SQLite introspection)
                if "PRAGMA" in line_text.upper():
                    continue
                # Skip parameterized queries — look for params (\"\"\", {...}) within 3000 chars
                after_match = content[m.end():m.end()+3000]
                # Pattern: closing quote(s) then ), then ,{ or ,(  (e.g. f\"\"\"...\"\"\", {params})
                if re.search(r'(?:["\']{1,3})\s*\)\s*,\s*(?:[\{([])', after_match):
                    continue
                # Skip Telegram API reply_text
                if "reply_text" in line_text:
                    continue
                # Skip if text() doesn't contain SQL keywords (likely not SQLAlchemy)
                matched = m.group(0)
                if "text(" in matched and not re.search(r'SELECT|INSERT|UPDATE|DELETE|CREATE|DROP', line_text, re.I):
                    continue

                findings.append(Finding(
                    rule_id=RULE_ID,
                    category="CRITICAL",
                    title=title,
                    file_path=str(fp),
                    line_number=line_no,
                    detail=f"Line {line_no}: {line_text[:120]}",
                    fix_suggestion=(
                        "Use parameterized queries / prepared statements instead of "
                        "string interpolation. For Python: cursor.execute(sql, (param,)). "
                        "For Rails: Model.where('col = ?', value)."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                ))

    return findings


description = "SQL injection via string interpolation (f-strings, %, .format, template literals)"
