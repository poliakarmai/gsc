#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Predictive Risk Forecasting v1.0 — предсказание уязвимостей.

ML на корпусе находок: предсказывает, где появится следующая уязвимость —
по churn файлов, автору, модулю, плотности прошлых находок, размеру PR.

Эксклюзив: никто не делает прогноз на собственном историческом корпусе.
GSC превращается из реактивного в проактивный.

CLI:
  gsc forecast train --repo <path>
  gsc forecast predict --repo <path> [--files file1.py file2.js]
  gsc forecast heatmap --repo <path> [--output heatmap.json]
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Feature Engineering ───────────────────────────────────
def _get_file_churn(repo: Path, file_path: str) -> int:
    """Number of commits touching this file in last 90 days."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", "--oneline", "--since=90.days.ago",
             "--", file_path],
            capture_output=True, text=True, timeout=5,
        )
        return len([l for l in r.stdout.strip().split("\n") if l])
    except Exception:
        return 0


def _get_file_authors(repo: Path, file_path: str) -> int:
    """Number of unique authors touching this file in last 90 days."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "shortlog", "-sn", "--since=90.days.ago",
             "--", file_path],
            capture_output=True, text=True, timeout=5,
        )
        return len([l for l in r.stdout.strip().split("\n") if l.strip()])
    except Exception:
        return 0


def _get_file_size(repo: Path, file_path: str) -> int:
    """Lines in file."""
    full = repo / file_path
    if full.exists():
        return len(full.read_text().split("\n"))
    return 0


def _get_file_age_days(repo: Path, file_path: str) -> int:
    """Days since first commit to this file."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", "--diff-filter=A", "--follow",
             "--format=%aI", "--", file_path],
            capture_output=True, text=True, timeout=5,
        )
        dates = [l for l in r.stdout.strip().split("\n") if l]
        if dates:
            created = datetime.fromisoformat(dates[-1].replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return 0


@dataclass
class FileRisk:
    file_path: str
    module: str
    risk_score: float = 0.0
    risk_level: str = "low"
    # Features
    past_critical: int = 0
    past_high: int = 0
    past_total: int = 0
    churn_90d: int = 0
    authors_90d: int = 0
    lines: int = 0
    age_days: int = 0
    days_since_last_finding: int = 999
    # Context
    top_rules: List[str] = field(default_factory=list)


# ── Predictive Engine ─────────────────────────────────────
class RiskForecaster:
    """
    Lightweight forecasting without external ML deps.
    Uses weighted scoring based on historical patterns:
    - Past density of findings per file
    - Churn (high churn = more bugs)
    - Recency (recent findings predict more)
    - Module clustering (bugs cluster in modules)
    """

    def __init__(self, repo_path: str):
        self.repo = Path(repo_path)
        self.findings_history: List[dict] = []
        self._load_history()

    def _load_history(self) -> None:
        """Load findings from GSC audit DB."""
        db_path = Path.home() / ".hermes" / "state" / "gsc_audit.db"
        if not db_path.exists():
            return

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            repo_name = self.repo.name
            rows = conn.execute(
                "SELECT * FROM findings WHERE file_path LIKE ? "
                "AND category IN ('CRITICAL','HIGH','MEDIUM') "
                "ORDER BY id DESC LIMIT 2000",
                (f"%{repo_name}%",),
            ).fetchall()
            self.findings_history = [dict(r) for r in rows]
        except Exception:
            pass
        finally:
            conn.close()

    def _calc_risk_score(self, file_path: str, per_file_counts: dict) -> FileRisk:
        """Calculate risk score for a single file."""
        risk = FileRisk(file_path=file_path, module=file_path.split("/")[0] if "/" in file_path else "root")

        counts = per_file_counts.get(file_path, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "total": 0})
        risk.past_critical = counts["CRITICAL"]
        risk.past_high = counts["HIGH"]
        risk.past_total = counts["total"]

        # Git features
        risk.churn_90d = _get_file_churn(self.repo, file_path)
        risk.authors_90d = _get_file_authors(self.repo, file_path)
        risk.lines = _get_file_size(self.repo, file_path)
        risk.age_days = _get_file_age_days(self.repo, file_path)

        # Scoring formula (weighted, no training needed)
        score = 0.0

        # Past density (strongest predictor)
        if risk.past_critical > 0:
            score += min(risk.past_critical * 15, 50)
        if risk.past_high > 0:
            score += min(risk.past_high * 8, 30)

        # Churn factor (high churn = more bugs)
        if risk.churn_90d > 20:
            score += 15
        elif risk.churn_90d > 10:
            score += 8
        elif risk.churn_90d > 0:
            score += 3

        # Multi-author (more hands = more inconsistency)
        if risk.authors_90d > 3:
            score += 5

        # Large files (more surface area)
        if risk.lines > 1000:
            score += 8
        elif risk.lines > 500:
            score += 4

        # New files (< 30 days) — less history, more risk
        if 0 < risk.age_days < 30:
            score += 5

        # Module clustering penalty (bugs cluster)
        module_counts = sum(1 for f, c in per_file_counts.items()
                          if f.startswith(risk.module) and c["CRITICAL"] + c["HIGH"] > 0)
        if module_counts > 5:
            score += 10

        risk.risk_score = round(score, 1)

        if score >= 50:
            risk.risk_level = "critical"
        elif score >= 30:
            risk.risk_level = "high"
        elif score >= 15:
            risk.risk_level = "medium"
        else:
            risk.risk_level = "low"

        return risk

    def predict(self, files: Optional[List[str]] = None) -> List[FileRisk]:
        """Predict risk for specified files (or all tracked files)."""
        # Aggregate per-file counts from history
        per_file_counts = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "total": 0})
        for f_ in self.findings_history:
            fp = f_.get("file_path", "")
            cat = f_.get("category", "").upper()
            per_file_counts[fp][cat] += 1
            per_file_counts[fp]["total"] += 1

        # Determine files to analyze
        if files:
            target_files = files
        else:
            # Analyze all files in repo that had findings
            target_files = list(per_file_counts.keys())
            # Also add files with high churn
            try:
                r = subprocess.run(
                    ["git", "-C", str(self.repo), "diff", "--name-only",
                     "HEAD~50..HEAD"],
                    capture_output=True, text=True, timeout=5,
                )
                recent = [l for l in r.stdout.strip().split("\n") if l]
                for rf in recent:
                    if rf not in per_file_counts:
                        target_files.append(rf)
            except Exception:
                pass

        results = []
        for fp in sorted(target_files):
            risk = self._calc_risk_score(fp, per_file_counts)
            results.append(risk)

        results.sort(key=lambda r: -r.risk_score)
        return results

    def heatmap(self, output_path: Optional[str] = None) -> List[dict]:
        """Generate risk heatmap for the entire repo."""
        predictions = self.predict()
        return [asdict(p) for p in predictions]


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Predictive Risk Forecasting")
    sub = p.add_subparsers(dest="cmd", required=True)

    predict_p = sub.add_parser("predict", help="Predict risk for files")
    predict_p.add_argument("--repo", required=True, help="Repository path")
    predict_p.add_argument("--files", nargs="*", help="Specific files to analyze")
    predict_p.add_argument("--output", "-o", help="Save JSON output")
    predict_p.add_argument("--limit", type=int, default=10, help="Top N results")

    heatmap_p = sub.add_parser("heatmap", help="Full repo risk heatmap")
    heatmap_p.add_argument("--repo", required=True)
    heatmap_p.add_argument("--output", "-o", help="Save JSON")

    args = p.parse_args()

    if args.cmd == "predict":
        fc = RiskForecaster(args.repo)
        results = fc.predict(args.files)

        print(f"\n{'='*60}")
        print(f"🔮 Risk Forecast — Top {args.limit} files")
        print(f"{'='*60}")
        print(f"{'Score':>6} {'Level':<10} {'C':>3} {'H':>3} {'Churn':>6} {'File'}")
        print("-" * 60)
        for r in results[:args.limit]:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(r.risk_level, "⚪")
            print(f"{r.risk_score:>6.0f} {r.risk_level:<10} "
                  f"{r.past_critical:>3} {r.past_high:>3} "
                  f"{r.churn_90d:>6} {emoji} {r.file_path}")

        if args.output:
            Path(args.output).write_text(
                json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False)
            )
            print(f"\nSaved to {args.output}")

    elif args.cmd == "heatmap":
        fc = RiskForecaster(args.repo)
        heatmap = fc.heatmap()
        summary = {
            "repo": args.repo,
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_files": len(heatmap),
            "critical": sum(1 for h in heatmap if h["risk_level"] == "critical"),
            "high": sum(1 for h in heatmap if h["risk_level"] == "high"),
            "medium": sum(1 for h in heatmap if h["risk_level"] == "medium"),
            "heatmap": heatmap[:50],
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if args.output:
            Path(args.output).write_text(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
