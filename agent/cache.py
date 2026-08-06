"""Локальный кэш findings для offline-режима."""
from __future__ import annotations

import json
from pathlib import Path


class FindingCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def store(self, repo_name: str, report: dict):
        path = self.cache_dir / f"{repo_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def mark_synced(self, repo_name: str):
        synced_marker = self.cache_dir / f"{repo_name}.synced"
        synced_marker.touch()

    def get_unsynced(self) -> list[str]:
        unsynced = []
        for p in self.cache_dir.glob("*.json"):
            repo_name = p.stem
            if not (self.cache_dir / f"{repo_name}.synced").exists():
                unsynced.append(repo_name)
        return sorted(unsynced)

    def load(self, repo_name: str) -> dict | None:
        path = self.cache_dir / f"{repo_name}.json"
        if not path.exists():
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def cleanup(self, keep_last: int = 10):
        for repo in set(p.stem for p in self.cache_dir.glob("*.json")):
            reports = sorted(self.cache_dir.glob(f"{repo}*.json"),
                             key=lambda p: p.stat().st_mtime,
                             reverse=True)
            for old in reports[keep_last:]:
                old.unlink(missing_ok=True)