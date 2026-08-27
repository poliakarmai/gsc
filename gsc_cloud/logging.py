# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Structured logging for the GSC Cloud API (DD-09).

Two coordinated concerns:

1. ``JsonFormatter`` — turns every ``logging.LogRecord`` into a single-line JSON
   document (ISO-8601 UTC timestamp, level, logger name, message, plus any
   ``extra=...`` fields the caller attached). Suitable for log shippers
   (Vector, Loki, Datadog). Stdlib only — no ``structlog`` / ``loguru``.

2. ``RequestIdMiddleware`` — pure-ASGI middleware that pins a per-request
   correlation id (``X-Request-ID`` header in, generated UUID4 hex prefix out)
   and exposes it to the rest of the request lifecycle through a
   :mod:`contextvars` token. The formatter pulls the value out of the
   contextvar so every log line emitted inside the request carries the same
   id without callers having to thread it through.

``configure_logging(level, fmt)`` is the single entry point used by the API
server to wire the formatter onto the ``gsc_cloud`` logger.
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
import traceback
import uuid
from datetime import datetime, timezone
from typing import Optional

# ── request-id contextvar ───────────────────────────────────────────
# Default None so the formatter can cheaply skip the field when no request
# is in flight (CLI tools, background workers, startup logs).
request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)


def set_request_id(value: Optional[str]) -> contextvars.Token:
    """Bind ``value`` as the current request id. Returns the reset token.

    Pair with ``request_id_var.reset(token)`` in a ``finally`` block (the
    ASGI middleware does this for you).
    """
    return request_id_var.set(value)


def get_request_id() -> Optional[str]:
    """Return the active request id, or ``None`` if no request is in flight."""
    return request_id_var.get()


# ── record fields that must NOT be re-emitted as JSON keys ──────────
# These are the standard LogRecord attributes (and ``message`` / ``asctime``
# which logging.Formatter may set on the record). Anything outside this set
# is treated as caller-supplied ``extra=...`` data and copied verbatim into
# the JSON output.
_RESERVED_RECORD_KEYS: frozenset[str] = frozenset({
    "name", "msg", "args", "levelname", "levelno",
    "pathname", "filename", "module", "exc_info", "exc_text",
    "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName",
    "process", "taskName", "message", "asctime",
})


class JsonFormatter(logging.Formatter):
    """Render ``LogRecord`` instances as one-line JSON documents.

    Output shape (always-present keys):

    * ``timestamp`` — ISO-8601 UTC with ``+00:00`` offset.
    * ``level``     — record level name (INFO/DEBUG/...).
    * ``logger``    — logger name.
    * ``message``   — formatted message string (args interpolated).

    Optional keys: every attribute of the record that is not in
    ``_RESERVED_RECORD_KEYS`` (typically the caller's ``extra=...`` payload),
    plus ``exc_info`` (traceback text) when an exception is attached, and
    ``request_id`` when the contextvar is set.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003 — std API
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Caller-supplied extra fields. Iterate the record's __dict__ (not
        # vars()) so we don't accidentally pick up Formatter internals.
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_KEYS or key in payload:
                continue
            if key.startswith("_"):
                # Private attributes (e.g. LogRecord internals) — skip.
                continue
            payload[key] = value

        # Exception traceback, if any. traceback.format_exc() needs sys.exc_info;
        # record.exc_info is the canonical source set by logger.exception().
        if record.exc_info:
            try:
                payload["exc_info"] = "".join(
                    traceback.format_exception(*record.exc_info)
                )
            except Exception:  # pragma: no cover — defensive
                payload["exc_info"] = str(record.exc_info)

        # request_id from contextvar (None => omit).
        rid = request_id_var.get()
        if rid is not None:
            payload["request_id"] = rid

        # default=str so non-JSON-native values (datetime, UUID, exceptions)
        # degrade to their repr() rather than crashing the log call.
        return json.dumps(payload, default=str, ensure_ascii=False)


# ── human-readable formatter (local dev) ────────────────────────────
_TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(
    level: int = logging.INFO, fmt: str = "json"
) -> None:
    """Wire the ``gsc_cloud`` logger to stderr.

    Args:
        level: numeric logging level (defaults to ``logging.INFO``).
        fmt: ``"json"`` for the structured ``JsonFormatter`` (production),
            ``"text"`` for the human-readable format used in local dev.
    """
    logger = logging.getLogger("gsc_cloud")

    # Wipe any handlers the caller (or a previous configure_logging call)
    # may have attached. We own the logger's handler list from here on.
    for h in list(logger.handlers):
        logger.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    elif fmt == "text":
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
    else:
        raise ValueError(
            f"Unknown log format: {fmt!r} (expected 'json' or 'text')"
        )
    logger.addHandler(handler)
    logger.setLevel(level)
    # Don't bubble to the root logger — gsc_cloud is the named logger for
    # this subsystem and double-emit is worse than silent elsewhere.
    logger.propagate = False


# ── ASGI middleware ─────────────────────────────────────────────────
_INCOMING_REQUEST_ID_HEADER = "x-request-id"
_OUTGOING_REQUEST_ID_HEADER = "X-Request-ID"


def _extract_incoming_request_id(headers) -> Optional[str]:
    """Return the first ``X-Request-ID`` value from raw ASGI headers, if any.

    ASGI delivers headers as a list of ``(bytes, bytes)`` pairs in
    latin-1. Header names are case-insensitive (RFC 9110), so we compare
    lowercased forms.
    """
    for raw_name, raw_value in headers:
        if raw_name.decode("latin-1").lower() != _INCOMING_REQUEST_ID_HEADER:
            continue
        try:
            value = raw_value.decode("latin-1").strip()
        except UnicodeDecodeError:
            return None
        if value:
            return value
    return None


class RequestIdMiddleware:
    """Pure-ASGI middleware that pins a per-request correlation id.

    Behaviour:

    * If the client sent ``X-Request-ID``, we adopt that value verbatim
      (after stripping whitespace and rejecting empty values).
    * Otherwise we mint a fresh ``uuid4().hex[:16]``.
    * The id is published to ``request_id_var`` for the duration of the
      request and reset in a ``finally`` block so requests don't leak
      ids into background tasks.
    * The same id is echoed back on the ``http.response.start`` message
      as the ``X-Request-ID`` response header.

    Lifespan / websocket scopes are passed through untouched.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = (
            _extract_incoming_request_id(scope.get("headers", []))
            or uuid.uuid4().hex[:16]
        )
        token = request_id_var.set(request_id)
        try:
            outgoing_name = _OUTGOING_REQUEST_ID_HEADER.encode("latin-1")
            outgoing_value = request_id.encode("latin-1")

            async def send_with_request_id(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((outgoing_name, outgoing_value))
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, send_with_request_id)
        finally:
            request_id_var.reset(token)


# ── entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":  # pragma: no cover — manual smoke check
    configure_logging(level=logging.INFO, fmt="json")
    logging.getLogger("gsc_cloud").info(
        "logging smoke test",
        extra={"component": "logging", "ok": True},
    )
