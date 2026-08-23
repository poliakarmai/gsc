#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Correct GS999-AI mis-attribution of quality semantic patterns.

The one-time attribution fix (commit d75a7f7) marked NULL-rule_id findings
"by echelon": every echelon-3 finding became GS999-AI. But echelon-3 also
carries quality semantic patterns (noise_tier='quality') from patterns/*.json
— Rust: .clone() in hot path, Go: Goroutine leak, sync.Mutex copy,
the Russian-language "sync code in async" pattern, TS: useEffect missing
deps, etc. Those are code smells, not AI findings.

This corrects them: quality semantic patterns → GS000-LEGACY + category=INFO
(matching check_adversarial's noise_tier='quality' → INFO rule). Genuine AI
findings (deep-reducer JSON detail / Russian analysis text) stay GS999-AI.

Idempotent. Dry-run by default; pass --apply to write.

Usage:
  python3 scripts/gsc_backfill_gs999ai.py          # report only
  python3 scripts/gsc_backfill_gs999ai.py --apply  # write
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"

# Severity values downgraded to INFO for quality (non-security) patterns.
_NON_INFO_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "redirect",
                        "ssrf", "injection", "supply-chain", "csrf",
                        "jwt", "command-injection", "buffer-overflow",
                        "path-traversal")


def quality_titles(conn: sqlite3.Connection) -> set[str]:
    """Titles of noise_tier='quality' semantic patterns (live SSOT)."""
    cur = conn.cursor()
    cur.execute("""SELECT DISTINCT title FROM patterns
                   WHERE noise_tier='quality' AND pattern_type='semantic'""")
    return {r[0] for r in cur.fetchall() if r[0]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    args = ap.parse_args()

    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    titles = quality_titles(conn)
    if not titles:
        print("no noise_tier='quality' semantic patterns found in patterns table", file=sys.stderr)
        conn.close()
        return 1

    ph = ",".join("?" * len(titles))
    sentinels = ("GS999-AI", "GS999-unknown")
    c.execute(f"""SELECT COUNT(*) FROM findings
                  WHERE rule_id IN ({','.join('?' * len(sentinels))})
                    AND pattern_title IN ({ph})""",
              (*sentinels, *titles))
    to_fix = c.fetchone()[0]

    # Severity breakdown of what will be corrected
    c.execute(f"""SELECT category, COUNT(*) FROM findings
                  WHERE rule_id IN ({','.join('?' * len(sentinels))})
                    AND pattern_title IN ({ph})
                  GROUP BY category ORDER BY 2 DESC""",
              (*sentinels, *titles))
    print(f"sentinel findings that are quality semantic patterns: {to_fix}")
    print("  by category:")
    for r in c.fetchall():
        print(f"    {r[0]:12} {r[1]}")

    # How many stay in the AI sentinel (genuine AI)
    c.execute(f"""SELECT COUNT(*) FROM findings
                  WHERE rule_id IN ({','.join('?' * len(sentinels))})
                    AND pattern_title NOT IN ({ph})""",
              (*sentinels, *titles))
    remain = c.fetchone()[0]
    print(f"\nsentinel findings kept (non-quality / genuine AI): {remain}")

    if not args.apply:
        print("\n(DRY-RUN — pass --apply to write)")
        conn.close()
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = DB_PATH.with_suffix(f".db.bak-{stamp}")
    shutil.copy2(DB_PATH, bak)
    print(f"\nbackup → {bak}")

    c.execute(f"""UPDATE findings SET rule_id='GS000-LEGACY'
                  WHERE rule_id IN ({','.join('?' * len(sentinels))})
                    AND pattern_title IN ({ph})""",
              (*sentinels, *titles))
    rid_fixed = c.rowcount

    # Historical systemd-hardening findings landed in GS999-unknown before
    # the producer fix — re-home them to GS000-LEGACY as well.
    c.execute("""UPDATE findings SET rule_id='GS000-LEGACY'
                 WHERE rule_id='GS999-unknown'
                   AND pattern_title='Systemd security hardening'""")
    rid_fixed += c.rowcount

    c.execute(f"""UPDATE findings SET category='INFO'
                  WHERE rule_id='GS000-LEGACY'
                    AND pattern_title IN ({ph})
                    AND category IN ({','.join('?' * len(_NON_INFO_SEVERITIES))})""",
              tuple(titles) + _NON_INFO_SEVERITIES)
    cat_fixed = c.rowcount

    conn.commit()
    print(f"rule_id sentinel → GS000-LEGACY : {rid_fixed}")
    print(f"category downgraded → INFO     : {cat_fixed}")

    for s in sentinels:
        c.execute("SELECT COUNT(*) FROM findings WHERE rule_id=?", (s,))
        print(f"remaining {s} : {c.fetchone()[0]}")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
