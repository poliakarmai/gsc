# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS019 — Authentication & Session Weaknesses Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects auth/session vulnerabilities — #5 in fintech pentest reports:

- SMS exhaustion / no rate limiting on OTP sends
- Session fixation (no regeneration after login)
- Weak session token generation (predictable)
- Missing HttpOnly/Secure flags on session cookies
- JWT without expiration (immortal tokens)
- Hardcoded session secrets
- Missing MFA for sensitive operations
- Auth bypass via missing decorators
- OTP brute-force protection missing
- Password reset token weaknesses

Sources: 2026 Fintech Pentest Report, OWASP ASVS V2/V3, PCI-DSS 8
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS019"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Auth/session weaknesses — SMS exhaustion, session fixation, "
    "weak tokens, missing cookie flags, immortal JWT, OTP brute-force"
)

# ── Regex patterns ──────────────────────────────────────────────────────────

# 1. OTP/SMS send without rate limiting
OTP_SEND_PATTERNS = re.compile(
    r'def\s+(?:send_otp|send_sms|send_code|send_verification|'
    r'request_otp|otp_request)',
    re.IGNORECASE,
)

NO_COOLDOWN_CHECK = re.compile(
    r'(?:send_otp|send_sms|send_code).*'
    r'(?!.*(?:cooldown|rate_limit|RateLimit|throttle|last_sent|'
    r'resend.*(?:second|minute|hour)|wait|delay|backoff))',
    re.IGNORECASE | re.DOTALL,
)

# 2. Session fixation — login without session regeneration
LOGIN_PATTERNS = re.compile(
    r'def\s+(?:login|signin|sign_in|log_in)\s*\(',
    re.IGNORECASE,
)

NO_SESSION_REGENERATION = re.compile(
    r'(?:login|signin|sign_in|log_in).*'
    r'(?!.*(?:session\\.regenerate|session_regenerate_id|'
    r'new_session|clear_session|session\\.clear|logout.*before|'
    r'request\\.session\\.clear|flush.*session|rotate.*session|'
    r'contrib\.auth\.login|login\(request|cycle_key))',
    re.IGNORECASE | re.DOTALL,
)

# 3. Missing HttpOnly/Secure/SameSite on cookies
SET_COOKIE_PATTERNS = re.compile(
    r'(?:set_cookie|Set-Cookie|response\.set_cookie|'
    r'response\.headers\[.Set-Cookie|make_response.*set_cookie)',
    re.IGNORECASE,
)

MISSING_COOKIE_FLAGS = re.compile(
    r'set_cookie\\([^)]+\\)'
    r'(?!.*(?:httponly|HttpOnly|secure|Secure|samesite|SameSite))',
    re.IGNORECASE | re.DOTALL,
)

# 4. JWT without expiration
JWT_NO_EXPIRATION = re.compile(
    r'(?:jwt\\.encode|jwt\\.sign|create_access_token|'
    r'create_refresh_token|JWT\\.encode)\\([^)]*\\)',
    re.IGNORECASE,
)

NO_EXP_CHECK = re.compile(
    r'(?:jwt\\.encode|create_access_token).*'
    r'(?!.*(?:exp(?:ires)?|expiration|expiry|exp_delta|'
    r'timedelta|datetime\\.utcnow|time\\.time|EXPIRATION))',
    re.IGNORECASE | re.DOTALL,
)

# 5. Hardcoded session/flask secret
SESSION_SECRET_HARDCODED = re.compile(
    r'(?:SESSION_SECRET|FLASK_SECRET|SECRET_KEY|JWT_SECRET|'
    r'APP_SECRET|CSRF_SECRET|session_secret)\s*=\s*["\']'
    r'(?!.*(?:os\.environ|os\.getenv|env\.get|config\(|'
    r'getenv|process\.env|import.*secret))'
    r'([^"\']{4,})["\']',
    re.IGNORECASE,
)

# Flask/object dict-assignment: app.config['SECRET_KEY'] = 'value'
FLASK_CONFIG_SECRET_HARDCODED = re.compile(
    r"(?:config|CONFIG)\s*\[['\"]?(?:SESSION_|FLASK_|APP_|CSRF_)?"
    r"(?:SECRET|secret)[_\s]?(?:KEY|key)?['\"]?\s*\]\s*=\s*['\"]"
    r"([^'\"]{4,})['\"]",
    re.IGNORECASE,
)

# 6. Missing MFA for sensitive operations
SENSITIVE_OPS = re.compile(
    r'def\s+(?:withdraw|transfer|payout|delete_account|'
    r'change_password|reset_password|update_email|add_payment_method)',
    re.IGNORECASE,
)

NO_MFA_CHECK = re.compile(
    r'(?:withdraw|transfer|payout|delete_account|change_password).*'
    r'(?!.*(?:mfa|2fa|otp|totp|verify.*code|confirm.*code|'
    r'challenge|authenticator|second.*factor))',
    re.IGNORECASE | re.DOTALL,
)

# 7. Decorator-based auth bypass (missing @login_required, @auth_required)
ROUTE_PATTERN = re.compile(
    r'@(?:app|router|bp|blueprint|routes)\\.(?:route|get|post|put|delete|patch)',
    re.IGNORECASE,
)

AUTH_DECORATORS = re.compile(
    r'@(?:login_required|auth_required|authenticated|'
    r'require_auth|jwt_required|token_required|'
    r'permission_required|role_required|has_permission|'
    r'authorize|guard)',
    re.IGNORECASE,
)

# 8. OTP without brute-force protection
OTP_VERIFY_PATTERNS = re.compile(
    r'def\s+(?:verify_otp|check_otp|validate_otp|verify_code|'
    r'confirm_code|verify_sms|check_code)',
    re.IGNORECASE,
)

NO_BRUTE_FORCE = re.compile(
    r'(?:verify_otp|check_otp|verify_code).*'
    r'(?!.*(?:attempt|retry|fail.*count|lock|block|'
    r'throttle|rate_limit|max.*try|too_many))',
    re.IGNORECASE | re.DOTALL,
)

# 9. Password reset token weaknesses
RESET_TOKEN_PATTERNS = re.compile(
    r'def\s+(?:reset_password|forgot_password|password_reset|'
    r'generate_reset_token|create_reset_token)',
    re.IGNORECASE,
)

WEAK_RESET_TOKEN = re.compile(
    r'(?:reset.*token|token.*reset)\s*=\s*'
    r'(?:random\.randint|random\.choice|str\(uuid|hashlib\.md5|'
    r'["\'].{1,16}["\']|secrets\.token_hex\([1-7]\))',
    re.IGNORECASE,
)


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _has_auth_decorator(content: str, route_pos: int) -> bool:
    """Check if a route has auth decorators within preceding 5 lines."""
    lines_before = content[max(0, route_pos - 500):route_pos].split("\n")
    recent = "\n".join(lines_before[-6:])
    return bool(AUTH_DECORATORS.search(recent))


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS019" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # 1. OTP/SMS send without rate limiting
        otp_funcs = OTP_SEND_PATTERNS.finditer(content)
        for match in otp_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'cooldown|rate_limit|RateLimit|throttle|'
                            r'last_sent|resend.*(?:second|minute|hour)|'
                            r'wait|delay|backoff|cool.*down|too_often',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"OTP/SMS send without rate limiting: {match.group(0)}",
                    detail="SMS/OTP send function lacks cooldown/throttle. Risk: SMS exhaustion, financial loss.",
                    fix_suggestion="Add cooldown (60s between sends per phone). Daily limit per number. Rate limit per IP.",
                    noise_tier="precise",
                ))

        # 2. Session fixation
        login_funcs = LOGIN_PATTERNS.finditer(content)
        for match in login_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'session\\.regenerate|session_regenerate_id|'
                            r'new_session|clear_session|session\\.clear|'
                            r'logout.*before|flush.*session|rotate.*session|'
                            r'request\\.session\\.clear',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Login without session regeneration: {match.group(0)}",
                    detail="Session ID not regenerated after login. Vulnerable to session fixation.",
                    fix_suggestion="Call session.regenerate() or session_regenerate_id() immediately after successful authentication.",
                    noise_tier="normal",
                ))

        # 3. Missing cookie flags
        for match in MISSING_COOKIE_FLAGS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Cookie set without HttpOnly/Secure/SameSite flags",
                detail=match.group(0)[:120],
                fix_suggestion="Add httponly=True, secure=True, samesite='Strict' to all session/auth cookies.",
                noise_tier="precise",
            ))

        # 4. JWT without expiration
        jwt_encodes = JWT_NO_EXPIRATION.finditer(content)
        for match in jwt_encodes:
            ctx_end = min(match.end() + 2000, len(content))
            ctx_body = content[match.start():ctx_end]
            if not re.search(r'exp(?:ires)?\\b|expiration|expiry|exp_delta|'
                            r'timedelta|datetime\\.utcnow|time\\.time\\b|'
                            r'EXPIRATION|access_token_expire',
                            ctx_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title="JWT created without expiration claim",
                    detail="JWT.encode without 'exp' claim. Tokens are immortal.",
                    fix_suggestion="Always set 'exp' claim on all JWTs. Max 15 minutes for access tokens, 7 days for refresh tokens.",
                    noise_tier="precise",
                ))

        # 5. Hardcoded session secrets
        for match in SESSION_SECRET_HARDCODED.finditer(content):
            secret_value = match.group(1)
            if any(skip in secret_value.lower() for skip in
                   ('***', 'your-', 'changeme', 'placeholder', 'example', 'os.environ')):
                continue
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Hardcoded session/JWT secret: {match.group(0).strip()[:100]}",
                detail="Session/JWT secret hardcoded in source. Anyone with code access can forge tokens.",
                fix_suggestion="Load from environment variable or secrets manager. Use random 64+ char secret.",
                noise_tier="precise",
                secret_value=secret_value,
            ))

        # 5b. Hardcoded secrets via Flask/object dict-assignment
        for match in FLASK_CONFIG_SECRET_HARDCODED.finditer(content):
            secret_value = match.group(1)
            if any(skip in secret_value.lower() for skip in
                   ('***', 'your-', 'changeme', 'placeholder', 'example', 'os.environ')):
                continue
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Hardcoded session/JWT secret (config dict-assignment): {match.group(0).strip()[:100]}",
                detail="Session/JWT secret hardcoded via app.config[]. Anyone with code access can forge tokens.",
                fix_suggestion="Load from environment variable or secrets manager. Use random 64+ char secret.",
                noise_tier="precise",
                secret_value=secret_value,
            ))

        # 6. Missing MFA on sensitive operations
        sensitive_funcs = SENSITIVE_OPS.finditer(content)
        for match in sensitive_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'mfa|2fa|otp|totp|verify.*code|confirm.*code|'
                            r'challenge|authenticator|second.*factor|'
                            r'verification.*code',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Sensitive operation without MFA: {match.group(0)}",
                    detail="Withdraw/transfer/password-change without second factor. PCI-DSS 8.3 requires MFA for sensitive ops.",
                    fix_suggestion="Add OTP/TOTP challenge before executing sensitive operations.",
                    noise_tier="normal",
                ))

        # 7. Auth bypass — routes without @auth_required
        all_routes = ROUTE_PATTERN.finditer(content)
        for match in all_routes:
            # Check only non-trivial routes (not /health, /ping, /status)
            route_line = content[match.end():min(match.end() + 200, len(content))]
            if re.search(r'(?:/health|/ping|/status|/metrics|/ready)', route_line):
                continue
            if not _has_auth_decorator(content, match.start()):
                # Get the function definition line
                func_match = re.search(
                    r'def\s+(\w+)',
                    content[match.end():min(match.end() + 500, len(content))]
                )
                func_name = func_match.group(1) if func_match else "unknown"
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Route without auth decorator: {func_name}",
                    detail=f"Route '{func_name}' lacks @login_required or equivalent. May be intentional (public API) or an oversight.",
                    fix_suggestion="Verify this route is intentionally public. If protected, add @login_required decorator.",
                    noise_tier="normal",
                ))

        # 8. OTP verify without brute-force protection
        otp_verifies = OTP_VERIFY_PATTERNS.finditer(content)
        for match in otp_verifies:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'attempt|retry|fail.*count|lock|block|'
                            r'throttle|rate_limit|max.*try|too_many|'
                            r'MAX_ATTEMPTS|attempts_left',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"OTP verification without brute-force protection: {match.group(0)}",
                    detail="OTP verify function lacks attempt counting/lockout. 6-digit OTP = 1M combinations, brute-forceable.",
                    fix_suggestion="Limit to 5 attempts per OTP. Add exponential backoff. Lock account after 10 failed attempts.",
                    noise_tier="precise",
                ))

        # 9. Weak password reset token
        reset_funcs = RESET_TOKEN_PATTERNS.finditer(content)
        for match in reset_funcs:
            func_end = min(match.start() + 2000, len(content))
            func_body = content[match.start():func_end]
            if WEAK_RESET_TOKEN.search(func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Weak password reset token generation: {match.group(0)}",
                    detail="Reset token uses predictable source (randint, short string, MD5). Tokens can be guessed.",
                    fix_suggestion="Use secrets.token_urlsafe(32) or equivalent cryptographically-secure random generator. Min 256 bits entropy.",
                    noise_tier="precise",
                ))

    return findings
