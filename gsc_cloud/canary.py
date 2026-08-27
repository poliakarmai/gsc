#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GSC Canary Deploy — gradual rollout of new detectors.

Feature flags control which detectors run at what percentage.
New detectors start at 5% → 25% → 100% as confidence builds.

Inspired by triagebot-action's staged pipeline + Brikman ch.5 (canary deploy).

Usage:
  python3 -m cloud.canary status              # show all canary detectors
  python3 -m cloud.canary promote GS032 --pct 25  # promote to 25%
  python3 -m cloud.canary rollback GS032       # emergency rollback
  python3 -m cloud.canary list                 # show all managed detectors
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

CANARY_FILE = Path(os.environ.get(
    "GSC_CANARY_PATH",
    str(Path.home() / ".hermes/state/gsc_canary.json")
))


@dataclass
class CanaryFlag:
    rule_id: str
    pct: int = 5               # percentage of repos that get this detector
    since: str = ""             # ISO timestamp when first deployed
    promoted_at: str = ""       # last promotion timestamp
    min_confidence: float = 0.70  # minimum confidence for findings
    rollback_reason: str = ""   # why rolled back (if pct=0)
    fp_rate: float = 0.0        # observed false positive rate
    error_rate: float = 0.0     # observed error rate
    notes: str = ""

    def is_active(self, repo_identifier: str) -> bool:
        """Deterministic canary: hash(repo + rule) % 100 < pct."""
        if self.pct <= 0:
            return False
        if self.pct >= 100:
            return True
        bucket = int(hashlib.md5(f"{repo_identifier}:{self.rule_id}".encode()).hexdigest(), 16) % 100
        return bucket < self.pct

    def is_ready_for_promotion(self) -> bool:
        """Check if canary is ready for next tier."""
        if self.pct >= 100:
            return False
        hours_since_promote = 0
        if self.promoted_at:
            try:
                promoted = time.mktime(time.strptime(self.promoted_at[:19], "%Y-%m-%dT%H:%M:%S"))
                hours_since_promote = (time.time() - promoted) / 3600
            except ValueError:
                pass
        return (
            hours_since_promote >= 24 and  # at least 24h at current level
            self.fp_rate < 0.05 and         # FP rate < 5%
            self.error_rate < 0.01          # error rate < 1%
        )


# ── Canary Store ───────────────────────────────────────────────────────

class CanaryStore:
    """Persistent canary configuration (JSON file)."""

    def __init__(self, path: Path = CANARY_FILE):
        self.path = path
        self.flags: dict[str, CanaryFlag] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            data = json.loads(self.path.read_text())
            for rid, entry in data.items():
                self.flags[rid] = CanaryFlag(
                    rule_id=rid,
                    pct=entry.get("pct", 5),
                    since=entry.get("since", ""),
                    promoted_at=entry.get("promoted_at", ""),
                    min_confidence=entry.get("min_confidence", 0.70),
                    rollback_reason=entry.get("rollback_reason", ""),
                    fp_rate=entry.get("fp_rate", 0.0),
                    error_rate=entry.get("error_rate", 0.0),
                    notes=entry.get("notes", ""),
                )

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for rid, flag in self.flags.items():
            data[rid] = {
                "rule_id": rid,
                "pct": flag.pct,
                "since": flag.since,
                "promoted_at": flag.promoted_at,
                "min_confidence": flag.min_confidence,
                "rollback_reason": flag.rollback_reason,
                "fp_rate": flag.fp_rate,
                "error_rate": flag.error_rate,
                "notes": flag.notes,
            }
        self.path.write_text(json.dumps(data, indent=2))

    def add(self, rule_id: str, pct: int = 5, min_confidence: float = 0.70) -> CanaryFlag:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        flag = CanaryFlag(
            rule_id=rule_id, pct=pct, since=now,
            promoted_at=now, min_confidence=min_confidence,
        )
        self.flags[rule_id] = flag
        self._save()
        return flag

    def get(self, rule_id: str) -> Optional[CanaryFlag]:
        return self.flags.get(rule_id)

    def promote(self, rule_id: str, pct: int) -> CanaryFlag:
        flag = self.flags.get(rule_id)
        if not flag:
            raise KeyError(f"Canary '{rule_id}' not found. Use add() first.")

        if pct < flag.pct:
            raise ValueError(
                f"Cannot demote from {flag.pct}% to {pct}%. "
                f"Use rollback() for emergency, or add a new canary."
            )

        flag.pct = pct
        flag.promoted_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save()
        return flag

    def rollback(self, rule_id: str, reason: str = "") -> CanaryFlag:
        flag = self.flags.get(rule_id)
        if not flag:
            raise KeyError(f"Canary '{rule_id}' not found.")
        flag.pct = 0
        flag.rollback_reason = reason or "Manual rollback"
        self._save()
        return flag

    def update_metrics(self, rule_id: str, fp_rate: float, error_rate: float):
        flag = self.flags.get(rule_id)
        if flag:
            flag.fp_rate = fp_rate
            flag.error_rate = error_rate
            self._save()

    def list_all(self) -> list[CanaryFlag]:
        return sorted(self.flags.values(), key=lambda f: f.rule_id)

    def list_active(self) -> list[CanaryFlag]:
        return [f for f in self.flags.values() if 0 < f.pct < 100]

    def list_ready_for_promotion(self) -> list[CanaryFlag]:
        return [f for f in self.list_active() if f.is_ready_for_promotion()]


# ── Canary check for workers ───────────────────────────────────────────

def should_run_detector(rule_id: str, repo_identifier: str) -> bool:
    """Check if a detector should run for this repo (canary gating)."""
    store = CanaryStore()
    flag = store.get(rule_id)
    if flag is None:
        return True  # not in canary → full rollout
    return flag.is_active(repo_identifier)


# ── CLI ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    store = CanaryStore()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        flags = store.list_all()
        if not flags:
            print("No canary flags configured.")
            sys.exit(0)
        print(f"{'Rule ID':12s} {'Pct':>4s} {'FP%':>6s} {'Err%':>6s} {'Ready':>6s} Since")
        print("-" * 55)
        for f in flags:
            ready = "✓" if f.is_ready_for_promotion() else ""
            print(f"{f.rule_id:12s} {f.pct:>3d}% {f.fp_rate:>5.1f}% {f.error_rate:>5.1f}% {ready:>5s}  {f.since[:10]}")

    elif cmd == "add":
        rid = sys.argv[2]
        pct = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        flag = store.add(rid, pct)
        print(f"✓ Added canary: {flag.rule_id} at {flag.pct}%")

    elif cmd == "promote":
        rid = sys.argv[2]
        pct = int(sys.argv[3]) if len(sys.argv) > 3 else 25
        flag = store.promote(rid, pct)
        print(f"✓ Promoted {flag.rule_id}: {flag.pct}%")

    elif cmd == "rollback":
        rid = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else ""
        flag = store.rollback(rid, reason)
        print(f"✓ Rolled back {flag.rule_id}: {flag.pct}% ({flag.rollback_reason})")

    elif cmd == "ready":
        ready = store.list_ready_for_promotion()
        if ready:
            print("Ready for promotion:")
            for f in ready:
                print(f"  {f.rule_id}: {f.pct}% → {min(f.pct*5, 100)}% (FP={f.fp_rate:.1%}, Err={f.error_rate:.1%})")
        else:
            print("No detectors ready for promotion.")

    elif cmd == "metrics":
        rid = sys.argv[2]
        fp = float(sys.argv[3])
        err = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
        store.update_metrics(rid, fp, err)
        print(f"✓ Updated metrics for {rid}: FP={fp:.1%}, Err={err:.1%}")

    else:
        print(f"Unknown command: {cmd}")
        print("Usage: canary {status|add|promote|rollback|ready|metrics} [args]")
