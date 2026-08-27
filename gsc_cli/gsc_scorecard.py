# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC Developer Security Scorecard v1.0.

Per-developer security score = насколько автор «расчистил» свой техдолг
по уязвимостям + бонус за подтверждённые (TP) фиксы.

Семантика (v1, честная и воспроизводимая):
  introduced = находки, чья уязвимая строка приписана автору (git blame)
  fixed      = из них — со status IN ('fixed','by_design') ИЛИ resolved_at NOT NULL
  confirmed  = из них — status='confirmed' (TP, подтверждено DAST/revalidate)

  debt_cleared_rate = fixed / introduced
  verification_bonus = 0.1 × (confirmed / max(fixed,1))
  score = debt_cleared_rate × (1 + verification_bonus)      # ≤ ~1.1

Автор-атрибуция — через git blame (reuse gsc_archaeology._git_blame).
"""

from __future__ import annotations

import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# ── Pure scoring ─────────────────────────────────────────────

def compute_dev_score(introduced: int, fixed: int, confirmed: int = 0) -> dict:
    """Чистая функция score. introduced/fixed/confirmed — неотрицательные."""
    introduced = max(int(introduced), 0)
    fixed = min(max(int(fixed), 0), introduced)      # fixed ⊆ introduced
    confirmed = min(max(int(confirmed), 0), fixed)   # confirmed ⊆ fixed

    debt_cleared_rate = fixed / introduced if introduced > 0 else 0.0
    verification_bonus = 0.1 * (confirmed / max(fixed, 1))
    score = debt_cleared_rate * (1.0 + verification_bonus)

    return {
        "score": round(score, 3),
        "debt_cleared_rate": round(debt_cleared_rate, 3),
        "verification_bonus": round(verification_bonus, 3),
        "introduced": introduced,
        "fixed": fixed,
        "confirmed": confirmed,
    }


# ── Author attribution (git blame) ───────────────────────────

def blame_author(repo: Path, file_path: str, line: int) -> str:
    """Автор строки через git blame. '' при неудаче."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "blame", "-L", f"{line},{line}",
             "--porcelain", "--", file_path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return ""
        for ln in r.stdout.splitlines():
            if ln.startswith("author "):
                return ln[7:].strip()
    except Exception:
        return ""
    return ""


# ── Aggregation ─────────────────────────────────────────────

class DevScorecard:
    """Агрегирует per-author статистику из findings DB + git blame."""

    def __init__(self, db, repo_path: str):
        self.db = db
        self.repo = Path(repo_path)

    def score_project(self, project: str, limit: int = 200) -> list[dict]:
        """Leaderboard: [{author, score, debt_cleared_rate, introduced, fixed, confirmed}]."""
        rows = self._findings(project, limit)
        per_author = defaultdict(lambda: {"introduced": 0, "fixed": 0, "confirmed": 0})

        for row in rows:
            fp = row.get("file_path") or row.get("file")
            ln = row.get("line_number") or row.get("line")
            if not fp or not ln:
                continue
            author = blame_author(self.repo, fp, int(ln))
            if not author:
                continue

            status = (row.get("status") or "").lower()
            resolved = row.get("resolved_at") is not None
            per_author[author]["introduced"] += 1
            if status in ("fixed", "by_design") or resolved:
                per_author[author]["fixed"] += 1
            if status == "confirmed":
                per_author[author]["confirmed"] += 1

        leaderboard = []
        for author, stats in per_author.items():
            s = compute_dev_score(
                stats["introduced"], stats["fixed"], stats["confirmed"])
            leaderboard.append({"author": author, **s})
        leaderboard.sort(key=lambda x: (x["score"], x["introduced"]), reverse=True)
        return leaderboard

    def _findings(self, project: str, limit: int) -> list[dict]:
        try:
            rows = self.db.query(
                "SELECT file_path, line_number, status, resolved_at "
                "FROM findings WHERE project = ? AND file_path IS NOT NULL "
                "ORDER BY created_at DESC LIMIT ?",
                (project, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="GSC developer security scorecard")
    ap.add_argument("--repo", default=".", help="git repo path")
    ap.add_argument("--project", help="project name in findings DB")
    ap.add_argument("--limit", type=int, default=200, help="max findings to blame")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from gsc_core.gsc_db import GSCDatabase

    with GSCDatabase() as db:
        sc = DevScorecard(db, args.repo)
        board = sc.score_project(args.project or Path(args.repo).resolve().name,
                                 limit=args.limit)

    if args.json:
        import json
        print(json.dumps(board, ensure_ascii=False, indent=2))
        return

    print(f"{'author':<30} {'score':>6} {'cleared':>8} {'intr':>5} {'fix':>5} {'conf':>5}")
    for e in board:
        print(f"{e['author'][:29]:<30} {e['score']:>6.3f} "
              f"{e['debt_cleared_rate']:>7.0%} "
              f"{e['introduced']:>5} {e['fixed']:>5} {e['confirmed']:>5}")


if __name__ == "__main__":
    main()
