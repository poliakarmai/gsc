"""Single source of truth for outbound git target validation.

Both the API (server) and every worker must apply the *same* policy so a target
accepted at enqueue time is never rejected at dequeue time (audit GSC-01).

Pure policy — raises ValueError, no HTTP layer. The API wraps ValueError into
HTTPException(400); workers let it propagate (or catch at their boundary).
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

_DEFAULT_HOSTS = "github.com,gitlab.com,bitbucket.org"


def allowed_hosts() -> set[str]:
    """Allowlisted git hosts (lowercased, trailing-dot stripped)."""
    raw = os.environ.get("GSC_ALLOWED_GIT_HOSTS", _DEFAULT_HOSTS)
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}


def validate_target(target: str) -> str:
    """Validate an outbound git target and return the normalized host.

    Rejects (ValueError):
      - non-HTTPS schemes (http://, ssh://, git://, file://)
      - hosts outside the allowlist (SSRF/egress guard)
      - credentials embedded in the URL
      - empty/missing repository path
    """
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https":
        raise ValueError("only https:// git targets are allowed")
    if parsed.port not in (None, 443):
        raise ValueError(f"non-default port is not allowed: {parsed.port!r}")
    if not host or host not in allowed_hosts():
        raise ValueError(f"target host is not allowlisted: {host!r}")
    if parsed.username or parsed.password:
        raise ValueError("credentials in target URL are not allowed")
    if not parsed.path or parsed.path == "/":
        raise ValueError("repository path is required")
    return host
