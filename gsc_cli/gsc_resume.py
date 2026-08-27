"""
GSC Resume Scanner — Deepsec-inspired per-file state tracking.

Allows scans to resume after interruption. Each file gets a state record:
  pending → scanning → scanned → processed

Key features:
- Atomic file locking via locked_by_run_id (supports parallel workers)
- File hash tracking for change detection
- Analysis history (append-only, like Deepsec)
- Status filtering for targeted re-scans

Usage:
    from gsc_resume import FileStateManager
    fsm = FileStateManager(db_path, project, run_id)
    pending = fsm.get_pending_files()  # files to scan
    fsm.mark_scanned(file_path, candidates_count)
    fsm.mark_processed(file_path, findings_count)
"""
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


class FileStateManager:
    """Per-file scan state — enables resume after interruption."""

    STATUSES = ("pending", "scanning", "scanned", "processed", "skipped")

    def __init__(self, db_path: str, project: str, run_id: str | None = None):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self.project = project
        self.run_id = run_id or f"run-{int(time.time())}-{hashlib.md5(project.encode()).hexdigest()[:6]}"

    def _hash_file(self, path: Path) -> str | None:
        """Hash file content for change detection."""
        try:
            return hashlib.md5(path.read_bytes()).hexdigest()
        except Exception:
            return None

    # ── State tracking ────────────────────────────────────────────────────────

    def init_files(self, files: list[Path]) -> int:
        """Initialize state records for all project files. Returns count of new files."""
        count = 0
        now = datetime.now(timezone.utc).isoformat()

        for fp in files:
            rel_path = str(fp.relative_to(fp.parent.parent)) if fp.is_relative_to(Path.cwd()) else str(fp)
            fhash = self._hash_file(fp)

            try:
                self.db.execute(
                    """INSERT OR IGNORE INTO file_state
                       (project, file_path, file_hash, status, last_scan_run, last_scan_at)
                       VALUES (?, ?, ?, 'pending', ?, ?)""",
                    (self.project, rel_path, fhash, self.run_id, now)
                )
                if self.db.total_changes > 0:
                    count += 1
            except Exception:
                continue

        self.db.commit()
        return count

    def get_pending_files(self, status: str = "pending") -> list:
        """Get files that haven't been scanned yet."""
        rows = self.db.execute(
            "SELECT file_path, file_hash FROM file_state WHERE project=? AND status=?",
            (self.project, status)
        ).fetchall()
        return [(r["file_path"], r["file_hash"]) for r in rows]

    def get_resumable_files(self) -> list:
        """Get files that were scanning when interrupted."""
        rows = self.db.execute(
            "SELECT file_path FROM file_state WHERE project=? AND status='scanning' AND locked_by_run_id=?",
            (self.project, self.run_id)
        ).fetchall()
        return [r["file_path"] for r in rows]

    def lock_files(self, files: list) -> int:
        """Atomically lock files for this run. Returns count locked."""
        count = 0
        for fp in files:
            cur = self.db.execute(
                """UPDATE file_state SET status='scanning', locked_by_run_id=?
                   WHERE project=? AND file_path=? AND status='pending'""",
                (self.run_id, self.project, fp)
            )
            count += cur.rowcount
        self.db.commit()
        return count

    def mark_scanned(self, file_path: str, candidates_count: int = 0):
        """Mark file as scanned (regex pass done)."""
        fhash = None
        try:
            fhash = self._hash_file(Path(file_path).resolve())
        except Exception:
            pass

        self.db.execute(
            """UPDATE file_state SET status='scanned', candidates_count=?,
               file_hash=?, last_scan_at=?
               WHERE project=? AND file_path=?""",
            (candidates_count, fhash, datetime.now(timezone.utc).isoformat(),
             self.project, file_path)
        )
        self.db.commit()

    def mark_processed(self, file_path: str, findings_count: int = 0, analysis: dict | None = None):
        """Mark file as processed (AI analysis done)."""
        history = self._get_history(file_path)
        if analysis:
            history.append(analysis)

        self.db.execute(
            """UPDATE file_state SET status='processed', findings_count=?,
               analysis_history=?, last_scan_at=?
               WHERE project=? AND file_path=?""",
            (findings_count, json.dumps(history),
             datetime.now(timezone.utc).isoformat(),
             self.project, file_path)
        )
        self.db.commit()

    def mark_skipped(self, file_path: str, reason: str = ""):
        """Skip a file (non-code, test, etc.)."""
        self.db.execute(
            "UPDATE file_state SET status='skipped' WHERE project=? AND file_path=?",
            (self.project, file_path)
        )
        self.db.commit()

    def is_changed(self, file_path: str, path: Path) -> bool:
        """Check if file content changed since last scan."""
        row = self.db.execute(
            "SELECT file_hash FROM file_state WHERE project=? AND file_path=?",
            (self.project, file_path)
        ).fetchone()
        if not row or not row["file_hash"]:
            return True  # No previous state — treat as changed

        current_hash = self._hash_file(path)
        return current_hash != row["file_hash"]

    def reset_if_changed(self, file_path: str, path: Path) -> bool:
        """Reset file to pending if content changed. Returns True if reset."""
        if self.is_changed(file_path, path):
            self.db.execute(
                "UPDATE file_state SET status='pending', file_hash=NULL WHERE project=? AND file_path=?",
                (self.project, file_path)
            )
            self.db.commit()
            return True
        return False

    def release_locks(self):
        """Release all locks for this run (call on completion)."""
        self.db.execute(
            "UPDATE file_state SET locked_by_run_id=NULL WHERE locked_by_run_id=?",
            (self.run_id,)
        )
        self.db.commit()

    def release_stale_locks(self, max_age_seconds: int = 3600):
        """Release locks older than max_age_seconds (from crashed runs)."""
        cutoff = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """UPDATE file_state SET status='pending', locked_by_run_id=NULL
               WHERE status='scanning'
               AND last_scan_at < datetime(?, ?)""",
            (cutoff, f'-{max_age_seconds} seconds')
        )
        self.db.commit()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get scan progress statistics."""
        rows = self.db.execute(
            "SELECT status, COUNT(*) as cnt FROM file_state WHERE project=? GROUP BY status",
            (self.project,)
        ).fetchall()
        stats = {s: 0 for s in self.STATUSES}
        for r in rows:
            stats[r["status"]] = r["cnt"]
        stats["total"] = sum(stats.values())
        stats["completed"] = stats["processed"] + stats["skipped"]
        stats["remaining"] = stats["pending"] + stats["scanning"]
        stats["progress_pct"] = round(stats["completed"] / max(stats["total"], 1) * 100, 1)
        return stats

    # ── Private ───────────────────────────────────────────────────────────────

    def _get_history(self, file_path: str) -> list:
        row = self.db.execute(
            "SELECT analysis_history FROM file_state WHERE project=? AND file_path=?",
            (self.project, file_path)
        ).fetchone()
        if not row:
            return []
        try:
            return json.loads(row["analysis_history"] or "[]")
        except json.JSONDecodeError:
            return []

    def close(self):
        self.db.close()
