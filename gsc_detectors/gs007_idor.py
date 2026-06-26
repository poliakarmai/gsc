"""
GS007 — Insecure Direct Object Reference (IDOR) patterns.

Detects:
- Direct DB lookup by ID without ownership/permission check
- User-controlled IDs in URL params without authorization
- Missing access control in API endpoints

OWASP A01:2021 — Broken Access Control.
"""

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS007"
ECHELON = 2

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str]] = [
    # Python/Django: direct get() without permission check
    (r'\.objects\.get\s*\(\s*pk\s*=\s*request\.', "Django direct PK lookup without auth check"),
    (r'\.objects\.get\s*\(\s*id\s*=\s*request\.', "Django direct ID lookup without auth check"),
    (r'\.objects\.filter\s*\(\s*pk\s*=\s*request\.', "Django direct PK filter without auth check"),

    # FastAPI: path parameter used directly in DB without auth
    (r'@app\.\w+\(.*\{.*id.*\}.*\)\s*\n\s*def\s+\w+\(.*\):\s*\n\s*(?!.*current_user|.*Depends)', "FastAPI route without auth on ID param"),

    # Rails: find(params[:id]) without ownership check
    (r'\.find\s*\(\s*params\s*\[\s*:id\s*\]\s*\)\s*\n(?!.*current_user|.*authenticate)', "Rails find(params[:id]) without auth"),

    # SQL ORDER BY / LIMIT from request params
    (r'(?:ORDER\s+BY|LIMIT|OFFSET)\s+.*request\.(?:args|GET|POST)\s*\[', "SQL clause from unsanitized request params"),
]

# Skip patterns (legitimate use cases)
SKIP_PATTERNS = [
    r'login_required',
    r'permission_required',
    r'@authenticated',
    r'current_user',
    r'request\.user\.',
    r'\.filter\s*\(.*user\s*=',
    r'\.filter\s*\(.*owner\s*=',
]


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect IDOR patterns — direct object references without auth checks."""
    if "GS007" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files(extensions=(".py", ".rb", ".js", ".ts", ".php")):
        content = ctx.read_file(fp)
        for pattern, title in _PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue

                # Check surrounding context for auth checks
                ctx_start = max(0, m.start() - 200)
                ctx_end = min(len(content), m.end() + 100)
                surrounding = content[ctx_start:ctx_end]

                # Skip if auth check is nearby
                if any(re.search(s, surrounding, re.I) for s in SKIP_PATTERNS):
                    continue

                findings.append(Finding(
                    rule_id=RULE_ID,
                    category="HIGH",
                    title=title,
                    file_path=str(fp),
                    line_number=line_no,
                    detail=f"Line {line_no}: {line_text[:120]}",
                    fix_suggestion=(
                        "Verify the current user has permission to access this object. "
                        "Check ownership: filter by user_id or check object ownership "
                        "before returning data."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
                    ],
                ))

    return findings


description = "Insecure Direct Object Reference — missing auth/ownership checks on DB access"
