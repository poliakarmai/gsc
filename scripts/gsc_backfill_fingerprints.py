#!/usr/bin/env python3
"""Backfill pattern_fingerprint for findings. Resumable, batch 5000."""
import argparse, sqlite3, sys, time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "gsc"))
from gsc_cli.gsc_mutation_tracker import normalize_snippet, fingerprint

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"

def backfill(db_path, batch, dry_run):
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    total = conn.execute(
        "SELECT COUNT(*) c FROM findings WHERE pattern_fingerprint IS NULL"
    ).fetchone()[0]
    print(f"Remaining: {total}", file=sys.stderr)
    if dry_run or total == 0:
        conn.close(); return
    done, t0 = 0, time.time()
    while True:
        rows = conn.execute(
            "SELECT rowid AS id, pattern_title, file_path, detail "
            "FROM findings WHERE pattern_fingerprint IS NULL LIMIT ?",
            (batch,)).fetchall()
        if not rows: break
        updates = []
        for r in rows:
            sn = r[3] or ""
            norm = normalize_snippet(sn) if sn.strip() else f"{r[1]}:{r[2]}".lower()
            fp = fingerprint(norm) if norm else ""
            updates.append((fp, r[0]))
        conn.executemany(
            "UPDATE findings SET pattern_fingerprint=? WHERE rowid=?", updates)
        conn.commit()
        done += len(rows)
        elapsed = time.time() - t0
        eta = elapsed / done * (total - done) if done else 0
        print(f"  {done}/{total} ({done/total:.1%}) ETA {eta:.0f}s", file=sys.stderr)
    conn.close()
    print("Backfill complete", file=sys.stderr)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--batch", type=int, default=5000)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    backfill(DB_PATH, args.batch, args.dry_run)
