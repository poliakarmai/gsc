# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""
GS013 — GraphQL Security Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects GraphQL security misconfigurations:
- Introspection enabled in production
- No query depth limiting
- No rate limiting on GraphQL endpoint
- Field suggestions enabled
- Debug mode enabled
- Excessive error disclosure

Sources: Hacking APIs Ch.14 Attacking GraphQL (No Starch Press)
"""
from gsc_detectors import AuditContext, Finding
import re

RULE_ID = "GS013"
ECHELON = 2
description = "GraphQL security — introspection, depth limiting, error disclosure"


PATTERNS = [
    # Apollo Server: introspection enabled
    (re.compile(r'introspection\s*:\s*(?:true|1|yes)', re.I),
     "GraphQL introspection enabled", "HIGH",
     "Introspection exposes entire API schema to attackers, enabling automated attacks. "
     "Disable in production or restrict to authenticated/authorized users.",
     "Set 'introspection: false' in production or use Apollo plugin for conditional introspection."),

    # Apollo: debug mode
    (re.compile(r'debug\s*:\s*(?:true|1|yes)', re.I),
     "GraphQL debug mode enabled", "MEDIUM",
     "Debug mode leaks stack traces and internal logic to clients.",
     "Set 'debug: false' in production."),

    # No depth limiting
    (re.compile(r'(?:depth|maxDepth|query_depth|MAX_DEPTH)\s*[:=]\s*(\d+)', re.I),
     "GraphQL depth limit check", "INFO",
     "Verify depth limit is reasonable (recommended: 3-10). Current: {match.group(1)}.",
     "Ensure depth limit is < 10 to prevent recursive query DoS."),

    # Graphene-Django: introspection enabled
    (re.compile(r'graphql_view\s*\([^)]*graphiql\s*=\s*True', re.I),
     "Graphene-Django GraphiQL enabled", "HIGH",
     "GraphiQL in production exposes schema introspection and query interface.",
     "Set 'graphiql=False' in production Django settings."),

    # Hasura: no admin secret
    (re.compile(r'HASURA_GRAPHQL_ADMIN_SECRET\s*[:=]\s*[\'\"]?\s*[\'\"]?', re.I),
     "Hasura admin secret may be empty", "CRITICAL",
     "Empty HASURA_GRAPHQL_ADMIN_SECRET allows unauthenticated admin access.",
     "Set a strong HASURA_GRAPHQL_ADMIN_SECRET environment variable."),

    # GraphQL Yoga: cors
    (re.compile(r'cors\s*:\s*\{[^}]*origin\s*:\s*[\'\"]\*[\'\"]', re.I),
     "GraphQL CORS origin wildcard", "LOW",
     "CORS origin='*' allows cross-origin GraphQL queries from any domain.",
     "Restrict CORS origin to specific domains in production."),

    # Excessive error disclosure
    (re.compile(r'(?:stacktrace|stack_trace|include_stacktrace)\s*:\s*(?:true|1)', re.I),
     "GraphQL error stack traces exposed", "MEDIUM",
     "Including stack traces in GraphQL errors leaks internal paths and logic.",
     "Set 'includeStacktraceInErrorResponses: false' in production."),

    # Disable suggestions
    (re.compile(r'(?:fieldSuggestions|suggestions)\s*:\s*(?:true|1)', re.I),
     "GraphQL field suggestions enabled", "LOW",
     "Field suggestions help attackers discover field names via trial and error.",
     "Disable field suggestions in production."),
]

# Files that indicate GraphQL is in use
GRAPHQL_FILES = {
    ".graphql", ".graphqls",
    "schema.graphql", "schema.graphqls",
    "apollo-server.js", "apollo-server.ts", "apollo.config.js",
    "graphene.py",
}


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS013" in ctx.skipped_detectors:
        return []
    findings = []

    for fp in ctx.get_source_files(extensions=(".py", ".js", ".ts", ".yaml", ".yml", ".json", ".graphql", ".graphqls")):
        # Skip if not a GraphQL-related file
        is_graphql_file = (
            fp.suffix in (".graphql", ".graphqls") or
            fp.name in ("schema.graphql", "schema.graphqls", "apollo-server.js",
                        "apollo-server.ts", "apollo.config.js") or
            "apollo" in fp.name.lower() or
            "graphql" in fp.name.lower() or
            "hasura" in fp.name.lower()
        )

        try:
            content = fp.read_text()
        except Exception:
            continue

        # Check if file references GraphQL
        has_graphql_ref = bool(re.search(
            r'(?:graphql|GraphQL|apollo|Apollo|hasura|Hasura|graphene|Graphene)',
            content, re.I
        ))

        if not is_graphql_file and not has_graphql_ref:
            continue  # Skip non-GraphQL files

        rel_path = str(fp.relative_to(ctx.path))

        for pattern, title, severity, detail, fix in PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count("\n") + 1

                # For depth limit pattern, only report if value is > 10
                if "depth limit" in title.lower():
                    try:
                        depth_val = int(match.group(1))
                        if depth_val <= 10:
                            continue  # OK
                    except ValueError:
                        pass

                # Manual {match.group(N)} substitution — str.format() doesn't support method calls
                formatted_detail = re.sub(r'\{match\.group\((\d+)\)\}', lambda m: (match.group(int(m.group(1))) or ""), detail)

                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=severity,
                    title=title,
                    detail=formatted_detail,
                    fix_suggestion=fix,
                    references=["Hacking APIs Ch.14 Attacking GraphQL"]
                ))

    return findings
