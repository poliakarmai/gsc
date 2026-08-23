#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Normalize historical rule_id / pattern_title pollution in gsc_audit.db.

The rule_id column accumulated three pollution classes over time (before the
`_derive_rule_id` attribution fix landed):

  1. rule_id = full pattern TITLE (e.g. "SQL injection risk: f-string in query",
     "Rust: .clone() in hot path", "Python: assert in production") — should be a GS0XX code.
  2. rule_id = "GS001 (Hardcoded secrets ...)" — GS code with the title glued on.
  3. rule_id = NULL (sink never ran) and pattern_title = NULL (producer never set it).

This backfill re-derives rule_id FROM SOURCE (pattern_title / title), never
blindly: a title is mapped through the same keyword table as `_derive_rule_id`
in gsc_cli/main.py. YAML-* custom rule IDs are left untouched. GS999 sentinels
are left untouched (their provenance is a different question).

Idempotent. Dry-run by default; pass --apply to write.

Usage:
  python3 scripts/gsc_backfill_rule_ids.py          # report only
  python3 scripts/gsc_backfill_rule_ids.py --apply  # write
"""

from __future__ import annotations

import argparse
import re
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"

# Valid GS-coded rule_id: GS0XX or GS0XX-subtype or sentinel GS999-*.
_GS_CODE_RE = re.compile(r"^GS\d{3}(?:-|$)")

# Custom YAML rule IDs (YAML-XXXXXXXX) — valid, leave as-is.
_YAML_ID_RE = re.compile(r"^YAML-[0-9A-F]{8}$")


def derive_rule_id(title: str) -> str:
    """Replica of gsc_cli.main._derive_rule_id — title → GS0XX (by source)."""
    t = (title or "").lower()
    if "sql" in t:
        return "GS005"
    if "xss" in t:
        return "GS020"
    if any(k in t for k in ("secret", "credential", "token", "encrypt",
                            "exposed", "hardcoded")):
        return "GS029"
    if "disclos" in t:
        return "GS014"
    if "eval" in t:
        return "GS008"
    if "pickle" in t or "deserial" in t:
        return "GS037"
    if "except" in t:
        return "GS010"
    if "docker" in t or "container" in t:
        return "GS031"
    return "GS000-LEGACY"


def is_polluted(rule_id: str | None) -> bool:
    """True when rule_id is not a clean GS code, YAML id, or GS999 sentinel."""
    if not rule_id:
        return True
    if _GS_CODE_RE.match(rule_id) or rule_id.startswith("GS999"):
        return False
    if _YAML_ID_RE.match(rule_id):
        return False
    return True


def clean_gs_prefix(rule_id: str) -> str | None:
    """Extract a valid GS code from a glued value like
    'GS001 (Hardcoded secrets in source code ...)' → 'GS001'."""
    m = re.match(r"^(GS\d{3})\b", rule_id)
    return m.group(1) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    args = ap.parse_args()

    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    # ── 1. rule_id normalization ──────────────────────────────────────────
    c.execute("SELECT COUNT(*) FROM findings WHERE rule_id IS NULL OR rule_id = ''")
    null_rid = c.fetchone()[0]

    c.execute("""SELECT rule_id, COUNT(*) FROM findings
                 WHERE rule_id IS NOT NULL AND rule_id != ''
                 GROUP BY rule_id ORDER BY 2 DESC""")
    all_rids = c.fetchall()
    polluted = [(r, n) for r, n in all_rids if is_polluted(r)]
    total_polluted = sum(n for _, n in polluted)

    print(f"findings with NULL/empty rule_id : {null_rid}")
    print(f"findings with polluted rule_id   : {total_polluted} "
          f"({len(polluted)} distinct values)")
    print(f"  top polluted values:")
    for r, n in polluted[:15]:
        print(f"    {n:6}  {r[:65]}")

    # ── 2. pattern_title backfill ─────────────────────────────────────────
    c.execute("""SELECT COUNT(*) FROM findings
                 WHERE pattern_title IS NULL OR pattern_title = ''""")
    null_pt = c.fetchone()[0]
    print(f"\nfindings with NULL/empty pattern_title : {null_pt}")

    if not args.apply:
        print("\n(DRY-RUN — pass --apply to write)")
        conn.close()
        return 0

    # ── Backup before write ───────────────────────────────────────────────
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = DB_PATH.with_suffix(f".db.bak-{stamp}")
    shutil.copy2(DB_PATH, bak)
    print(f"\nbackup → {bak}")

    # Normalize rule_id from source (pattern_title preferred, then title).
    updated_rid = 0
    for (rid, n) in polluted:
        # Glued GS code → strip to GS0XX.
        glued = clean_gs_prefix(rid)
        if glued:
            c.execute("UPDATE findings SET rule_id=? WHERE rule_id=?",
                      (glued, rid))
            updated_rid += c.rowcount
            continue
        # Title-shaped rule_id → re-derive per-row (title differs per row).
        c.execute("""SELECT id, title, pattern_title FROM findings WHERE rule_id=?""",
                  (rid,))
        rows = c.fetchall()
        for _id, title, pt in rows:
            new_rid = derive_rule_id(pt or title or rid)
            if new_rid != rid:
                c.execute("UPDATE findings SET rule_id=? WHERE id=?", (new_rid, _id))
                updated_rid += 1

    # NULL rule_id → derive from pattern_title/title.
    c.execute("""SELECT id, title, pattern_title FROM findings
                 WHERE rule_id IS NULL OR rule_id = ''""")
    for _id, title, pt in c.fetchall():
        new_rid = derive_rule_id(pt or title or "")
        c.execute("UPDATE findings SET rule_id=? WHERE id=?", (new_rid, _id))
        updated_rid += 1

    # Backfill NULL pattern_title from title.
    updated_pt = 0
    c.execute("""SELECT id, title FROM findings
                 WHERE pattern_title IS NULL OR pattern_title = ''""")
    for _id, title in c.fetchall():
        if title:
            c.execute("UPDATE findings SET pattern_title=? WHERE id=?", (title, _id))
            updated_pt += 1

    conn.commit()
    print(f"rule_id normalized : {updated_rid}")
    print(f"pattern_title backfilled : {updated_pt}")

    # Post-state summary
    c.execute("""SELECT COUNT(*) FROM findings WHERE rule_id IS NULL OR rule_id=''""")
    print(f"remaining NULL rule_id : {c.fetchone()[0]}")
    c.execute("""SELECT COUNT(*) FROM findings WHERE pattern_title IS NULL OR pattern_title=''""")
    print(f"remaining NULL pattern_title : {c.fetchone()[0]}")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
