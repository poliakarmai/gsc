# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Per-API-key rate limiting for the GSC Cloud API (DD-07).

Sliding-window limiter keyed by the raw ``x-api-key`` header (the same header
``apideps.tenant_ctx`` authenticates). A request is rejected with HTTP 429 when
the key exceeds ``limit`` requests inside ``window`` seconds.

Backend: in-memory (thread-safe, per-process). Honest about the limitation —
for multi-replica deployments the window is per-process, so the limiter
under-counts. The shared backend (Redis, reusing the pattern in ``dedup.py``)
is the follow-up; this in-memory limiter is correct for a single-worker pilot
and is the natural seam to swap later.

Anti-brute-force note (audit): this limiter is keyed on ``x-api-key`` and runs
AFTER ``tenant_ctx``, so it throttles only *authenticated* keys — unauthenticated
key-guessing is NOT rate-limited here (each random key gets its own bucket).
That is acceptable because keys are 256-bit random (``gsk_`` + token_urlsafe),
so brute-forcing is infeasible; and a per-IP limiter belongs at the reverse
proxy (nginx/ingress) where ``X-Forwarded-For`` is trustworthy, not in-app
where it is spoofable. Follow-up card: DD-11.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException


class SlidingWindowLimiter:
    """Thread-safe in-memory sliding-window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: float) -> bool:
        """True if the request is allowed; False if ``limit`` is reached.

        Uses ``time.monotonic`` (not wall-clock) so the window is stable across
        NTP/system-clock adjustments.

        Memory is bounded by the finite set of *valid* API keys: this limiter
        runs AFTER ``tenant_ctx``, so only authenticated keys ever reach it
        (the unauthenticated path 401s first). A full TTL sweep would only be
        needed if the limiter were moved in front of auth.
        """
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


# Process-global limiter shared by all tenants' keys.
_LIMITER = SlidingWindowLimiter()


def rate_limit(
    limit: int,
    window: float = 60.0,
    resource: str = "",
) -> "callable":
    """FastAPI dependency factory: per-API-key sliding-window limit.

    Keyed on the raw ``x-api-key`` header so the limit applies per credential,
    independent of the tenant it resolves to. Raises HTTP 429 with a
    ``Retry-After`` hint when the window is exhausted.
    """

    def _dep(x_api_key: str = Header(default="")) -> None:
        key = f"{resource}:{x_api_key}" if x_api_key else f"{resource}:<anon>"
        if not _LIMITER.allow(key, limit, window):
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
                headers={"Retry-After": str(int(window))},
            )

    return _dep
