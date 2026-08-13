# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS015 — Python Entry Point Coverage Detector (Inspired by Deepsec)
Echelon: 1 (SOURCE)
Noise Tier: noisy

Marks every Python HTTP handler as a candidate for AI review.
Does NOT flag vulnerabilities — just ensures the AI sees every entry point.

Covers: Flask, FastAPI, Django, Sanic, Tornado, aiohttp, Falcon, Bottle
"""
from gsc_detectors import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS015"
ECHELON = 1
NOISE_TIER = "noisy"
description = "Entry-point coverage — marks HTTP handlers for AI review (noisy matcher)"


# Entry point patterns for Python frameworks
ENTRY_PATTERNS = [
    # FastAPI / Starlette
    (re.compile(r'@\w+\.(?:get|post|put|delete|patch|options|head|route)\s*\(', re.I),
     "FastAPI/Starlette route handler", "fastapi"),
    
    # Flask
    (re.compile(r'@\w+\.(?:route|get|post|put|delete|patch)\s*\(', re.I),
     "Flask route handler", "flask"),
    
    # Django views (class-based)
    (re.compile(r'class\s+\w+\((?:APIView|ViewSet|ModelViewSet|GenericAPIView)', re.I),
     "Django REST class-based view", "django"),
    
    # Django views (function-based)
    (re.compile(r'@api_view\s*\(', re.I),
     "Django REST function-based view", "django"),
    
    # Sanic
    (re.compile(r'@\w+\.(?:get|post|put|delete|patch|route|websocket)\s*\(', re.I),
     "Sanic route handler", "sanic"),
    
    # Tornado
    (re.compile(r'class\s+\w+\s*\(\s*(?:tornado\.web\.)?RequestHandler', re.I),
     "Tornado request handler", "tornado"),
    
    # aiohttp
    (re.compile(r'async\s+def\s+\w+\s*\(\s*request\s*:\s*(?:aiohttp\.)?\w*Request', re.I),
     "aiohttp request handler", "aiohttp"),
    
    # Falcon
    (re.compile(r'class\s+\w+\s*\(\s*:\s*Resource', re.I),
     "Falcon resource handler", "falcon"),

    # Generic HTTP method handlers
    (re.compile(r'def\s+(?:do_GET|do_POST|do_PUT|do_DELETE|do_PATCH)\s*\(', re.I),
     "BaseHTTPServer handler", "generic"),
    
    # WSGI/ASGI apps
    (re.compile(r'(?:app|application)\s*=\s*\w+\(', re.I),
     "WSGI/ASGI application entry", "generic"),
]

# Paths to skip — not real entry points, just demo/test/sample code
_SKIP_PATH_PATTERNS = re.compile(
    r'(?:/|\A)(?:tests?|fixtures?|examples?|samples?|demo|docs?)/',
    re.IGNORECASE)
TARGET_GLOBS = [
    "**/routes/**/*.py",
    "**/views/**/*.py", 
    "**/handlers/**/*.py",
    "**/api/**/*.py",
    "**/endpoints/**/*.py",
    "**/controllers/**/*.py",
    "**/routers/**/*.py",
    "**/app.py",
    "**/main.py",
    "**/server.py",
    "**/urls.py",
    "**/wsgi.py",
    "**/asgi.py",
]


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS015" in ctx.skipped_detectors:
        return []
    findings = []

    # Only target Python files in entry-point directories
    for fp in ctx.get_files(extensions=(".py",)):
        rel_path = str(fp.relative_to(ctx.path))
        
        # Check if file is in an entry-point location
        is_entry_point = any(
            fp.match(glob) for glob in TARGET_GLOBS
        )
        
        # Also check files that aren't in obvious entry-point dirs but contain routes
        if not is_entry_point:
            continue

        # Skip tests and non-code
        if ctx.is_test_file(fp) or ctx.is_non_code_file(fp):
            continue
        # Skip demo/test/sample directories
        if _SKIP_PATH_PATTERNS.search(rel_path):
            continue

        try:
            content = fp.read_text()
        except Exception:
            continue

        found_framework = None
        for pattern, title, framework in ENTRY_PATTERNS:
            matches = list(pattern.finditer(content))
            if matches:
                found_framework = framework
                
                # Report up to 10 entry points per file
                for match in matches[:10]:
                    lineno = content[:match.start()].count("\n") + 1
                    matched_text = match.group(0)[:60]
                    
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity="INFO",
                        title=title,
                        detail=f"Entry point detected: {matched_text}. "
                               f"Marked for AI security review.",
                        fix_suggestion="AI review will check for auth, rate limiting, input validation.",
                        noise_tier=NOISE_TIER,
                        references=["Deepsec-inspired entry-point coverage"]
                    ))

        # If file is in entry-point dir but no patterns matched, mark whole file
        if not found_framework and is_entry_point:
            findings.append(Finding(
                rule_id=RULE_ID,
                file_path=rel_path,
                line=1,
                severity="INFO",
                title="Entry-point directory file — AI review recommended",
                detail=f"File in entry-point directory ({rel_path.split('/')[0]}) "
                       f"with no recognized framework patterns. Manual review needed.",
                fix_suggestion="AI will review for custom framework security patterns.",
                noise_tier=NOISE_TIER,
                references=["Deepsec-inspired entry-point coverage"]
            ))

    return findings
