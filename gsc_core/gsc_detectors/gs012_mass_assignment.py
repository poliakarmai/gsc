# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS012 — Mass Assignment Vulnerability Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects mass assignment vulnerability patterns:
- Django: request.POST in create/update without fields/exclude
- FastAPI/Starlette: request data spread into model without filtering
- Rails: params in create/update without strong_params/permit
- Flask: request.form in model constructor without filtering
- GraphQL: mutations accepting full input objects without allowlists

Sources: Hacking APIs Ch.11 Mass Assignment (No Starch Press)
"""
from . import AuditContext, Finding
import re

RULE_ID = "GS012"
ECHELON = 2
description = "Mass Assignment — unfiltered request data in model create/update"


# Patterns from Hacking APIs Ch.11 and real-world mass assignment vulns
PATTERNS = [
    # Django: Model.objects.create(**request.POST)
    (re.compile(r'\.objects\.(?:create|update|get_or_create|update_or_create)\s*\(\s*\*\*\s*request\.(?:POST|DATA|body|json)', re.I),
     "Django mass assignment via **request.POST/DATA", "HIGH",
     "Unfiltered request data in model create/update allows role/privilege escalation. "
     "Use ModelForm with 'fields' or serializer with 'fields/exclude'.",
     "Use ModelForm with explicit 'fields' list or DRF serializer with defined fields."),

    # Django: instance.field = request.POST.get() then save()
    (re.compile(r'\.(?:save|update)\s*\(\s*\)', re.I),
     "Possible mass assignment — check for unfiltered request.POST", "LOW",
     "Generic save/update — may be safe. Verify surrounding context for request.POST usage.",
     "Review if request data is filtered before assignment."),

    # FastAPI/Starlette: **request.json() / **body.dict() spread
    (re.compile(r'\*\*\s*(?:request\.(?:json|body|form|data)|body\.(?:dict|model_dump))\s*\(\s*\)', re.I),
     "FastAPI mass assignment via **request.json() spread", "HIGH",
     "Unpacking request body directly into model enables field injection. "
     "Use Pydantic model with Field(exclude=True) or explicit field whitelist.",
     "Define Pydantic schema with only allowed fields, or use model_dump(exclude={'admin', 'role'})."),

    # Rails: Model.new(params) / Model.create(params) / model.update(params) without permit
    (re.compile(r'(?:\.new|\.create|\.update|\.update_attributes|\.assign_attributes)\s*\(\s*(?:params|request\.params)', re.I),
     "Rails mass assignment — params without permit/require", "HIGH",
     "Direct params in model create/update bypasses strong parameters. "
     "Use params.require(:model).permit(:field1, :field2).",
     "Add params.require(:model).permit(:allowed_fields) before model assignment."),

    # GraphQL: mutation accepting full input object
    (re.compile(r'mutation\s+\w+\s*\(?\s*\$?\w*\s*:\s*(?:String|Input|JSON)', re.I),
     "GraphQL mutation accepting unrestricted input", "MEDIUM",
     "Unrestricted input type in GraphQL mutation enables mass assignment. "
     "Define explicit input types with only allowed fields.",
     "Use GraphQL input types with allowlisted fields, add field-level authorization."),

    # JavaScript: Object.assign(user, req.body)
    (re.compile(r'Object\.(?:assign|spread)\s*\(\s*\w+\s*,\s*(?:req|request)\.(?:body|params|query)', re.I),
     "JS/TS mass assignment via Object.assign/spread with request body", "HIGH",
     "Assigning request body directly to object allows privilege escalation.",
     "Whitelist allowed fields: const {name, email} = req.body; user.name = name; user.email = email."),
]

# Secondary patterns (context-dependent)
CONTEXT_PATTERNS = [
    (re.compile(r'(?:fields|exclude)\s*=\s*\([^)]*\)|fields\s*=\s*\[[^\]]*\]|fields\s*=\s*\{[^}]*\}', re.I),
     "Explicit field whitelist detected — likely safe"),
    (re.compile(r'(?:require|permit)\s*\([^)]*\)', re.I),
     "Strong parameters pattern detected — likely safe"),
    (re.compile(r'(?:schema|Schema|serializer)\s*[:.]\s*(?:\w+Serializer|ModelSchema)', re.I),
     "Serializer/schema usage detected — verify fields are restricted"),
]


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS012" in ctx.skipped_detectors:
        return []
    findings = []

    for fp in ctx.get_source_files(extensions=(".py", ".rb", ".js", ".ts", ".graphql", ".graphqls")):
        try:
            content = fp.read_text()
        except Exception:
            continue

        rel_path = str(fp.relative_to(ctx.path))

        # First check for primary mass assignment patterns
        for pattern, title, severity, detail, fix in PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count("\n") + 1

                # Skip LOW severity if file is likely safe (has explicit field lists)
                if severity == "LOW":
                    # Check nearby context for filtering patterns
                    context_ok = any(
                        cp.search(content[max(0, match.start()-200):match.start()+200])
                        for cp, _ in CONTEXT_PATTERNS[:2]
                    )
                    if context_ok:
                        continue

                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=severity,
                    title=title,
                    detail=detail,
                    fix_suggestion=fix,
                    references=["Hacking APIs Ch.11 Mass Assignment", "OWASP API4:2023"]
                ))

    return findings
