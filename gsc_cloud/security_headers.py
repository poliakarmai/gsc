# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Security headers middleware for the GSC Cloud API (DD-08).

Adds defense-in-depth HTTP response headers to every response:

- Strict-Transport-Security (HSTS)
- X-Frame-Options: DENY (clickjacking)
- X-Content-Type-Options: nosniff (MIME sniffing)
- Referrer-Policy: no-referrer
- X-Permitted-Cross-Domain-Policies: none
- Content-Security-Policy: default-src 'self'; frame-ancestors 'none'

The middleware is idempotent: it never overwrites a header that an upstream
reverse proxy (nginx/ingress) already set, so a stricter operator policy wins.
"""
from __future__ import annotations

_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
]


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware: inject security headers on http.response.start.

    Pure ASGI (not BaseHTTPMiddleware) so it composes cleanly with
    CORSMiddleware and StreamingResponse without buffering the body.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {k.decode("latin-1").lower() for k, _ in headers}
                for name, value in _SECURITY_HEADERS:
                    if name.lower() not in existing:
                        headers.append(
                            (name.encode("latin-1"), value.encode("latin-1"))
                        )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
