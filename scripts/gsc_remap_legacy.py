#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""One-shot remap of GS000-LEGACY findings in gsc_audit.db.

GS000-LEGACY is the catch-all sentinel for legacy findings whose rule_id could
not be derived at scan time (pre-rule_id-migration scans, Cyrillic titles,
ambiguous patterns). It mixes real security findings with code-quality noise,
which pollutes precision measurements.

This script splits the sentinel bucket:
  - security titles/categories  → correct GS0XX rule_id (via gsc_rule_attribution)
  - code-quality titles         → noise_tier='quality' (stops counting as security)
  - remaining ambiguous         → left as GS000-LEGACY (never force-attributed)

Idempotent (only touches rule_id='GS000-LEGACY'). Dry-run by default.

Usage:
  python3 scripts/gsc_remap_legacy.py          # report only
  python3 scripts/gsc_remap_legacy.py --apply  # write (with backup)
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from datetime import datetime
from functools import lru_cache
from pathlib import Path

# Import the shared attribution module (repo root on sys.path when run from ~/gsc).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gsc_core.gsc_rule_attribution import (  # noqa: E402
    LEGACY_SENTINEL,
    QUALITY_TIER,
    attribute,
)

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"


@lru_cache(maxsize=None)
def _attribute(title: str, category: str) -> tuple[str, str]:
    return attribute(title, category)


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    args = ap.parse_args()

    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    c.execute(
        "SELECT id, COALESCE(NULLIF(pattern_title,''), NULLIF(title,''), ''), "
        "COALESCE(NULLIF(category,''), '') "
        "FROM findings WHERE rule_id='GS000-LEGACY'"
    )
    rows = c.fetchall()
    total = len(rows)
    print(f"GS000-LEGACY findings : {total}")

    remap_ids: dict[str, list[int]] = {}
    quality_ids: list[int] = []
    left = 0
    remap_by_rule: dict[str, int] = {}

    for _id, t, cat in rows:
        rid, tier = _attribute(t, cat)
        if rid != LEGACY_SENTINEL:
            remap_ids.setdefault(rid, []).append(_id)
            remap_by_rule[rid] = remap_by_rule.get(rid, 0) + 1
        elif tier == QUALITY_TIER:
            quality_ids.append(_id)
        else:
            left += 1

    remapped = sum(remap_by_rule.values())
    quality = len(quality_ids)

    print(f"  → remap to GS0XX      : {remapped}")
    print(f"  → noise_tier='quality' : {quality}")
    print(f"  → left as sentinel     : {left}")
    print(f"\nRemap targets:")
    for rid, n in sorted(remap_by_rule.items(), key=lambda kv: -kv[1]):
        print(f"    {rid:10s} {n}")

    if not args.apply:
        print("\n(DRY-RUN — pass --apply to write)")
        conn.close()
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = DB_PATH.with_suffix(f".db.bak-{stamp}")
    shutil.copy2(DB_PATH, bak)
    print(f"\nbackup → {bak}")

    for rid, ids in remap_ids.items():
        for chunk in _chunks(ids, 500):
            ph = ",".join("?" * len(chunk))
            c.execute(f"UPDATE findings SET rule_id=? WHERE id IN ({ph})", [rid, *chunk])

    for chunk in _chunks(quality_ids, 500):
        ph = ",".join("?" * len(chunk))
        c.execute(
            f"UPDATE findings SET noise_tier=? WHERE id IN ({ph})",
            [QUALITY_TIER, *chunk],
        )

    conn.commit()

    c.execute("SELECT COUNT(*) FROM findings WHERE rule_id='GS000-LEGACY'")
    remaining = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM findings WHERE noise_tier='quality'")
    quality_total = c.fetchone()[0]

    print(f"committed. remaining GS000-LEGACY : {remaining}")
    print(f"total noise_tier='quality'        : {quality_total}")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
