# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC Temporal Mutation Tracker v0.19.

Tracks return of "fixed" vulnerabilities:
  - recurrence: identical pattern came back (sim >= 0.95)
  - mutation:   pattern returned in modified form (0.50 <= sim < 0.95)

Parent = only resolved finding within lookback_days.
Alerts are always warn-only — never affect PR gate exit code.
"""

import hashlib, re
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Optional

DEFAULTS = {
    "lookback_days": 90,
    "similarity_min": 0.50,
    "similarity_recurrence": 0.95,
    "min_confidence": 0.55,
    "max_findings_per_scan": 50,
    "max_parent_candidates": 20,
    "auto_resolve_grace_days": 7,
}


def normalize_snippet(snippet: str) -> str:
    """Collapse cosmetic differences: comments, strings, numbers, variable names at assignment position."""
    if not snippet:
        return ""
    norm = re.sub(r"#.*$|//.*$", "", snippet, flags=re.MULTILINE)
    norm = re.sub(r'"[^"\n]*"|\'[^\'\n]*\'', '"STR"', norm)
    norm = re.sub(r"\b\d+(?:\.\d+)?\b", "NUM", norm)
    norm = re.sub(r"\b[a-zA-Z_]\w*(?=\s*=[^=])", "VAR", norm)
    norm = re.sub(r"\s+", " ", norm).strip().lower()
    return norm


def fingerprint(snippet: str) -> str:
    """sha256(normalized)[:16]. Fallback for empty snippets: rule_id+file."""
    norm = normalize_snippet(snippet)
    if not norm:
        return ""
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


@dataclass
class MutationAlert:
    finding_key: str
    parent_key: str
    parent_file: str
    parent_resolved_at: str
    kind: str       # "mutation" | "recurrence"
    similarity: float
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


class MutationMatcher:
    """Чистый матчер: без БД. Принимает список resolved-родителей.
    Используется и SQLite-трекером (v0.19), и cloud-инжестом (S2)."""

    def __init__(self, config: dict | None = None):
        cfg = {**DEFAULTS, **(config or {})}
        self.sim_min = float(cfg["similarity_min"])
        self.sim_recurrence = float(cfg["similarity_recurrence"])

    def match(self, finding: dict, norm_snippet: str,
              parent_rows: list) -> Optional[MutationAlert]:
        best = None
        for row in parent_rows:
            parent_norm = row.get("normalized_snippet") or \
                normalize_snippet(row.get("snippet") or
                                  row.get("detail") or "")
            if not parent_norm:
                continue
            sim = SequenceMatcher(None, norm_snippet, parent_norm).ratio()
            if sim >= self.sim_recurrence:
                kind = "recurrence"
            elif sim >= self.sim_min:
                kind = "mutation"
            else:
                continue
            if best is None or sim > best[0]:
                best = (sim, kind, row)
        if best is None:
            return None
        return self._build_alert(finding, best)

    def _build_alert(self, finding, best):
        sim, kind, row = best
        rule_id = finding.get("rule_id", finding.get("pattern_title", ""))
        if kind == "recurrence":
            msg = (f"Pattern {rule_id} was fixed "
                   f"{row.get('resolved_at', '?')} "
                   f"in {row.get('file_path', row.get('file', '?'))}, "
                   f"but returned identical (similarity {sim:.0%})")
        else:
            msg = (f"Pattern {rule_id} was fixed "
                   f"{row.get('resolved_at', '?')} "
                   f"in {row.get('file_path', row.get('file', '?'))}, "
                   f"but returned in mutated form "
                   f"(similarity {sim:.0%}). Likely copy-paste debt")
        return MutationAlert(
            finding_key=finding.get("finding_key", ""),
            parent_key=row.get("finding_key", "?"),
            parent_file=row.get("file_path", row.get("file", "?")),
            parent_resolved_at=row["resolved_at"],
            kind=kind,
            similarity=round(sim, 2),
            message=msg,
        )


class MutationTracker:
    """Tracks return of resolved vulnerability patterns."""

    def __init__(self, db, config: Optional[dict] = None):
        cfg = {**DEFAULTS, **(config or {})}
        self.db = db
        self.lookback_days = int(cfg["lookback_days"])
        self.min_confidence = float(cfg["min_confidence"])
        self.max_per_scan = int(cfg["max_findings_per_scan"])
        self.max_candidates = int(cfg["max_parent_candidates"])
        self.matcher = MutationMatcher(config)

    # ── Public API ─────────────────────────────────────────

    def process(self, findings: list[dict], target: str,
                scan_mode: str) -> list[MutationAlert]:
        """Called after dedup+scoring. Fingerprints all findings,
        searches for resolved parents."""
        alerts: list[MutationAlert] = []
        tracked = 0

        for f in findings:
            snippet = f.get("snippet", f.get("detail", ""))
            fp = fingerprint(snippet)
            norm = normalize_snippet(snippet)
            f.setdefault("metadata", {})["pattern_fingerprint"] = fp

            # Record sighting for auto-resolve
            fk = f.get("finding_key", "")
            if fk:
                try:
                    self.db.record_sighting(fk, target, scan_mode)
                except Exception:
                    pass

            if not fp or f.get("confidence", 0) < self.min_confidence:
                continue
            if tracked >= self.max_per_scan:
                continue
            tracked += 1

            alert = self._find_parent(f, norm)
            if alert:
                alerts.append(alert)
                f["metadata"]["mutation_alert"] = alert.kind
                f["metadata"]["mutation_parent"] = alert.parent_key
                try:
                    self.db.save_alert(alert)
                except Exception:
                    pass

        return alerts

    # ── Parent search ──────────────────────────────────────

    def _find_parent(self, finding: dict,
                     norm_snippet: str) -> Optional[MutationAlert]:
        rule_id = finding.get("rule_id", finding.get("pattern_title", ""))
        candidates = self.db.query("""
            SELECT id AS finding_key, file_path, detail, resolved_at
            FROM findings
            WHERE pattern_title LIKE ?
              AND resolved_at IS NOT NULL
              AND resolved_at > datetime('now', ?)
            ORDER BY resolved_at DESC
            LIMIT ?
        """, (f"%{rule_id}%", f"-{self.lookback_days} days",
              self.max_candidates)).fetchall()
        # Convert sqlite3.Row to dict-like for MutationMatcher
        parent_rows = [dict(r) for r in candidates]
        return self.matcher.match(finding, norm_snippet, parent_rows)


# ── Auto-resolve ──────────────────────────────────────────

def auto_resolve(db, target: str, current_keys: set, scan_mode: str,
                 grace_days: int = 7) -> int:
    """Mark findings as resolved when they disappear from full scans.

    Rules:
      - Only for scan_mode == 'full' (diff proves nothing)
      - Finding must have been seen in full scans of this target
      - Not seen for grace_days (branch flapping protection)
    """
    if scan_mode != "full":
        return 0

    try:
        rows = db.query("""
            SELECT DISTINCT s.finding_key
            FROM finding_sightings s
            WHERE s.target = ? AND s.scan_mode = 'full'
        """, (target,)).fetchall()
        # Filter: only findings that exist and are unresolved
        valid = []
        for r in rows:
            fk = r["finding_key"]
            try:
                exists = db.query(
                    "SELECT id FROM findings WHERE id = ? AND resolved_at IS NULL",
                    (fk,)).fetchone()
            except Exception:
                # Try matching by finding_key in metadata (computed hash)
                exists = None
            if exists:
                valid.append(fk)
        rows = [{"finding_key": k} for k in valid]
    except Exception:
        return 0

    resolved = 0
    for row in rows:
        key = row["finding_key"]
        if key in current_keys:
            continue
        try:
            last_seen = db.query("""
                SELECT MAX(seen_at) AS t FROM finding_sightings
                WHERE finding_key = ? AND target = ?
            """, (key, target)).fetchone()
            if not last_seen or not last_seen["t"]:
                continue
        except Exception:
            continue

        # Check grace period
        try:
            ok = db.query(
                "SELECT datetime('now', ?) <= ?",
                (f"-{grace_days} days", last_seen["t"])
            ).fetchone()
            if not ok:
                continue
        except Exception:
            continue

        try:
            db.execute("""
                UPDATE findings
                SET resolved_at = datetime('now'), resolved_by = 'auto'
                WHERE id = ? AND resolved_at IS NULL
            """, (key,))
            db.commit()
            resolved += 1
        except Exception:
            pass

    return resolved
