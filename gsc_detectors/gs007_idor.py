# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS007 — Broken Access Control: IDOR + BAC patterns.

Detects:
- Direct object reference without ownership/permission check (IDOR)
- Sequential/predictable ID enumeration (auto-increment, no UUID)
- Missing tenant/organization isolation (cross-org access)
- Support/admin/internal panel routes without auth
- Unprotected file/attachment download endpoints
- Operations on behalf of other users/orgs (create/edit/subscribe)

OWASP A01:2021 — Broken Access Control.
Inspired by: Meta $78K bounty (2026) — chained BAC in support infrastructure.
"""

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS007"
ECHELON = 2
NOISE_TIER = "normal"

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str]] = [
    # ── IDOR: Direct DB access ─────────────────────────────────────────────
    # Python/Django: direct get() without permission check
    (r'\.objects\.get\s*\(\s*pk\s*=\s*request\.', "Django direct PK lookup without auth check"),
    (r'\.objects\.get\s*\(\s*id\s*=\s*request\.', "Django direct ID lookup without auth check"),
    (r'\.objects\.filter\s*\(\s*pk\s*=\s*request\.', "Django direct PK filter without auth check"),

    # FastAPI: path parameter used directly in DB without auth
    (r'@app\.\w+\(.*\{.*id.*\}.*\)\s*\n\s*def\s+\w+\(.*\):\s*\n\s*(?!.*current_user|.*Depends)', "FastAPI route without auth on ID param"),

    # Rails: find(params[:id]) without ownership check
    (r'\.find\s*\(\s*params\s*\[\s*:id\s*\]\s*\)\s*\n(?!.*current_user|.*authenticate)', "Rails find(params[:id]) without auth"),

    # Express.js: req.params.id used directly in DB without auth middleware
    (r'(?:findById|findByPk|findOne)\s*\(\s*req\.params\.\w+\s*\)', "Express direct ID lookup without auth check"),
    # Laravel: Model::find($request->id) without auth
    (r'(?:\w+)::find\s*\(\s*\$request->\w+\s*\)', "Laravel Model::find without auth check"),

    # SQL ORDER BY / LIMIT from request params
    (r'(?:ORDER\s+BY|LIMIT|OFFSET)\s+.*request\.(?:args|GET|POST)\s*\[', "SQL clause from unsanitized request params"),

    # ── SEQUENTIAL ID ENUMERATION ──────────────────────────────────────────
    # Auto-increment PK in schema (enables enumeration) — word boundaries to avoid matching serializers/serialize
    (r'\b(?:AUTO_INCREMENT|AUTOINCREMENT|IDENTITY\s*\(\s*1\s*,\s*1\s*\)|nextval\s*\()', "Auto-increment PK enables ID enumeration (consider UUID)"),
    # PostgreSQL SERIAL/BIGSERIAL — with word boundaries (NOT serializers!)
    (r'\b(?:SERIAL|BIGSERIAL)\b', "PostgreSQL SERIAL PK enables ID enumeration"),
    # Integer ID from request without UUID validation
    (r'int\s*\(\s*(?:request\.(?:args|GET|POST|params))\s*\[', "Integer ID from request — predictable, enables enumeration"),
    # Loop iterating through sequential IDs
    (r'for\s+\w+\s+in\s+range\s*\(.*(?:id|ticket|order|user_id)', "Sequential ID iteration (potential enumeration attack)"),

    # ── CROSS-TENANT/ORG ISOLATION ─────────────────────────────────────────
    # Query without tenant/org filter
    (r'\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*request\.user\b', "User-scoped query missing org/tenant filter — cross-org access possible"),
    # Multi-tenant app: no tenant_id in WHERE clause
    (r'SELECT\s+.*FROM\s+\w+\s+WHERE\s+(?!.*tenant_id|.*org_id|.*organization_id).*\buser_id\s*=', "SQL query filtered by user_id only — missing tenant isolation"),
    # FastAPI: Depends(get_current_user) without Depends(get_current_org)
    (r'Depends\s*\(\s*get_current_user\s*\)\s*(?!.*Depends\s*\(\s*get_current_org)', "FastAPI with user auth but missing organization auth"),

    # ── ADMIN/SUPPORT PANEL EXPOSURE ───────────────────────────────────────
    # Admin routes without auth decorator
    (r'@(?:app|router|bp)\.\w+\(\s*[\'\"]/(?:admin|support|internal|staff|moderation)\b', "Admin/support route — verify auth decorator is present"),
    # Django admin-like views without @staff_member_required
    (r'def\s+\w+admin\w*\s*\(request.*\):\s*\n\s*(?!.*@\w+_required|.*permission)', "Django admin view without permission decorator"),
    # Flask blueprint for admin without @login_required
    (r"@\w+_blueprint\.route\s*\(\s*[\'\"]/(?:admin|support|internal)", "Flask admin/support blueprint route — verify auth"),

    # ── FILE/ATTACHMENT DOWNLOAD ───────────────────────────────────────────
    # File download endpoint with ID param, no ownership check
    (r'@(?:app|router)\.\w+\(\s*[\'\"].*(?:attachment|file|download|media).*\{.*\w+.*\}', "File/attachment download endpoint — verify ownership check"),
    # Django FileResponse with path from request
    (r'FileResponse\s*\(.*request\.(?:GET|POST).*\[', "File download path from request param — verify access control"),
    # Express: res.sendFile with req.params
    (r'(?:sendFile|download)\s*\(.*req\.(?:params|query)\.', "Express file send from request params — verify auth"),

    # ── TICKET/ORDER OPERATIONS ────────────────────────────────────────────
    # Create/update on behalf of another org
    (r'(?:create|update|delete|save)\s*\(.*request\.(?:data|body|POST).*org', "Ticket mutation — verify org membership before operation"),
    # Adding subscribers/participants without permission check
    (r'\badd_subscriber\b\s*\(', "Add subscriber/member operation — verify caller permission"),
    (r'\badd_participant\b\s*\(', "Add participant operation — verify caller permission"),
    # Status transition without ownership check
    (r'(?:status|state)\s*=\s*request\.(?:data|POST|body)\[.*[\"\'](?:status|state)', "Status change from request — verify caller owns this object"),

    # ── BATCH OPERATIONS (Gen+Eval PASS #1) ───────────────────────────────
    # Bulk create/update/delete without ownership check (Django, Sequelize, Mongoose, Laravel)
    (r'\b(?:bulk_create|bulk_update|insertMany|insert_many|bulkWrite|batchPut|batchDelete|bulk_save_objects)\s*\(', "Batch operation without ownership check"),

    # ── HTTP METHOD OVERRIDE (Gen+Eval PASS #4) ──────────────────────────
    # Method override bypass: X-HTTP-Method / _method → обход ACL
    (r'\b(?:HTTP_METHOD_OVERRIDE|X-HTTP-Method|X-HTTP-Method-Override)\b', "HTTP Method Override header — potential ACL bypass"),
    (r'\b_method\b\s*=', "HTTP method override via _method parameter — potential ACL bypass"),

    # ── FINTECH IDOR (2026 Pentest) ───────────────────────────────────────
    # Payment method access without ownership check
    (r'(?:payment_method|PaymentMethod|card|Card)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk)\s*=\s*',
     "Payment method/card lookup — verify ownership before exposing"),
    # Transaction/statement access by sequential ID
    (r'(?:transaction|Transaction|statement|Statement)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*.*request\.',
     "Transaction/statement lookup from request — verify account ownership"),
    # Bank account operations without ownership verification
    (r'(?:bank_account|BankAccount|account)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk|number)\s*=',
     "Bank account access — verify customer ownership"),
    # Invoice/bill access by ID
    (r'(?:invoice|Invoice|bill|Bill)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk|number)\s*=\s*request',
     "Invoice/bill access by request param — verify payer/recipient ownership"),
    # Balance/portfolio lookup by user ID (no auth check)
    (r'(?:balance|Balance|portfolio|Portfolio)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:user_id|account_id)\s*=\s*request',
     "Balance lookup by user_id from request — verify caller is the owner"),
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
    r'\.filter\s*\(.*org\s*=',
    r'\.filter\s*\(.*tenant\s*=',
    r'\.filter\s*\(.*organization\s*=',
    r'is_authenticated',
    r'has_permission\s*\(',
    r'has_perm\s*\(',
    r'user_passes_test',
    r'@staff_member_required',
    r'@admin_required',
    r'@role_required',
    r'uuid\s*\(\s*',
    r'UUID\s*\(\s*',
    r'isinstance\s*\(.*UUID',
    r'requireAuth|require_auth|withAuth|with_auth',
    r'middleware\s*\(\s*[\'\"]auth[\'\"]\s*\)',
    r'@UseGuards\s*\(\s*AuthGuard',
    r'@Protected\s*\(',
]


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect IDOR + BAC patterns — object references without auth checks."""
    if "GS007" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files(extensions=(".py", ".rb", ".js", ".ts", ".php", ".sql", ".java", ".go")):
        # Skip vendor/minified/static bundles
        fname = fp.name.lower()
        if any(x in fname for x in (".min.", "-bundle", "bundle.", "vendor", ".pack.")):
            continue
        if "static/" in str(fp) and (fname.endswith(".min.js") or "bundle" in fname):
            continue
        content = ctx.read_file(fp)
        for pattern, title in _PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue

                # Check surrounding context for auth checks
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(content), m.end() + 150)
                surrounding = content[ctx_start:ctx_end]

                # Skip if auth check is nearby
                if any(re.search(s, surrounding, re.I) for s in SKIP_PATTERNS):
                    continue

                # Determine severity based on pattern category
                severity = "HIGH"
                if "admin" in title.lower() or "support" in title.lower():
                    severity = "CRITICAL"
                elif "enumeration" in title.lower() or "auto-increment" in title.lower() or "SERIAL" in title:
                    severity = "INFO"  # facilitator, not vulnerability on its own

                findings.append(Finding(
                    rule_id=RULE_ID,
                    category=severity,
                    title=title,
                    file_path=str(fp),
                    line_number=line_no,
                    detail=f"Line {line_no}: {line_text[:120]}",
                    fix_suggestion=_get_fix_suggestion(title),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
                        "https://whiteauth.com/2026/07/17/broken-access-control-in-meta-com-support-infrastructure/",
                    ],
                ))

    return findings


def _get_fix_suggestion(title: str) -> str:
    """Return context-aware fix suggestion based on pattern type."""
    if "enumeration" in title.lower() or "auto-increment" in title.lower():
        return (
            "Use UUID/GUID instead of auto-increment IDs for external-facing resources. "
            "If sequential IDs are required, add rate limiting and ownership checks."
        )
    elif "tenant" in title.lower() or "org" in title.lower() or "cross-org" in title.lower():
        return (
            "Add tenant_id/org_id filter to all queries. "
            "Verify current_user belongs to the same organization as the requested resource. "
            "Implement organization-scoped querysets."
        )
    elif "admin" in title.lower() or "support" in title.lower():
        return (
            "Add authentication AND authorization decorators to admin/support routes. "
            "Implement role-based access control (RBAC). "
            "Consider IP allowlisting for admin panels."
        )
    elif "file" in title.lower() or "attachment" in title.lower() or "download" in title.lower():
        return (
            "Verify file ownership before serving. Use signed URLs with expiry. "
            "Implement access control check: does the requesting user own/ have permission to this file?"
        )
    elif "ticket" in title.lower() or "subscriber" in title.lower() or "status" in title.lower():
        return (
            "Verify the caller has permission to perform this operation on this object. "
            "Check organization membership and role before allowing mutations. "
            "Log all administrative operations for audit trail."
        )
    else:
        return (
            "Verify the current user has permission to access this object. "
            "Check ownership: filter by user_id or check object ownership "
            "before returning data."
        )


description = "Broken Access Control — IDOR, sequential ID enumeration, cross-tenant access, admin panel exposure, unprotected file downloads, unauthorized ticket operations"
