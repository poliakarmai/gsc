"""Taint model — track whether a value/action is downstream of untrusted input.

Ported conceptually from openworker (MIT, toolauth) and the not-sandboxed LLM firewall
(AGPL — mechanics only). The one invariant GSC enforces: a side-effecting action (write /
network / exfil) whose inputs derive from untrusted repo content must NOT be auto-approved.
GSC findings are by definition extracted from scanned (untrusted) repos; the taint flag
marks records whose *content* feeds a downstream action, so callers can gate auto-fixes,
tool-calls and LLM re-verdicts on it.
"""
from __future__ import annotations

from typing import Any

_TAINT_KEYS = ("_tainted", "taint")


def tainted(obj: Any, default: bool = False) -> bool:
    """True when ``obj`` (dict/finding) is marked as derived from untrusted content."""
    if isinstance(obj, dict):
        return any(bool(obj.get(k)) for k in _TAINT_KEYS)
    return default


def mark_tainted(obj: dict) -> dict:
    """Return a copy of ``obj`` flagged as downstream of untrusted repo content."""
    out = dict(obj)
    out["_tainted"] = True
    return out


def require_untainted(record: dict) -> bool:
    """Gate for side-effecting tool-calls: False when ``record`` is tainted.

    Callers that would auto-approve a write/network action on a tainted record must
    route it to a human decision instead.
    """
    return not tainted(record)
