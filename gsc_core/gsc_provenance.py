"""Provenance / data-lineage tracker — which files the agent created vs. the repo.

Ported conceptually from openworker (MIT, ``coworker/provenance.py``). In GSC the
rejudge/PoF path treats agent-generated files (``poc_verify.py``, patches) differently
from repo files: a verdict computed *on* an agent-created file must not be trusted the
way a repo file is. ``mark`` records origin; ``origin_of``/``is_agent_generated`` let
callers hold a file to that origin.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

_LOCK = threading.Lock()
_RECORDS: dict[str, dict] = {}


def mark(path, origin: str, step: str = "") -> None:
    """Record that ``path`` was produced by ``origin`` (e.g. ``"agent"`` vs ``"repo"``)."""
    _RECORDS[str(path)] = {"origin": origin, "step": step, "ts": time.time()}


def origin_of(path) -> Optional[str]:
    """The recorded origin of ``path``, or None when unknown (treat as repo)."""
    rec = _RECORDS.get(str(path))
    return rec["origin"] if rec else None


def is_agent_generated(path) -> bool:
    """True when ``path`` was recorded as agent-created (not part of the scanned repo)."""
    return origin_of(path) == "agent"


def lineage_summary() -> list:
    """Sorted [(path, origin, step, ts)] for audit/diagnostics (paths only, no content)."""
    return [
        {"path": p, "origin": r["origin"], "step": r["step"], "ts": r["ts"]}
        for p, r in sorted(_RECORDS.items())
    ]
