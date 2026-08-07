#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Cross-Repo Secret Correlation v1.0 — корреляция секретов между репозиториями.

Обнаруживает один и тот же секрет в разных репозиториях, отслеживает ротацию.
Fingerprint секрета — без хранения самого значения.

Эксклюзив: multi-repo visibility через fingerprint matching.
Killer-фича SaaS: «мы видим ваши секреты насквозь через все репозитории».

CLI:
  gsc secrets correlate --repos repo1 repo2 repo3
  gsc secrets status --key <secret_fingerprint>
  gsc secrets report --org <github-org>
"""

from __future__ import annotations

import hashlib


def fingerprint_secret(value: str) -> str:
    """Return 32-char SHA256 fingerprint. Value is NOT stored."""
    return hashlib.sha256(value.encode()).hexdigest()[:32]
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

# Module-level patterns for tests
ORIGINAL_PATTERNS = [
    (r'[A-Za-z0-9+/=]{40,}', 'api_key'),
    (r'\b[0-9a-fA-F]{32,64}\b', 'hex_key'),
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
]
REFINED_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY', 'private_key'),
    (r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\'"]?([A-Za-z0-9+/=_.-]{12,})', 'config_secret'),
    (r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s\'"]{10,}', 'db_url'),
]

GSC_HOME = Path.home() / ".gsc"
SECRETS_DB = GSC_HOME / "crossrepo_secrets.db"


# ── Database ───────────────────────────────────────────────
def _connect() -> sqlite3.Connection:
    GSC_HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SECRETS_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS secret_fingerprints (
            fingerprint TEXT PRIMARY KEY,          -- sha256(value)[:32] — NEVER store the value itself!
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            repo_count INTEGER DEFAULT 1,
            total_sightings INTEGER DEFAULT 1,
            rotated INTEGER DEFAULT 0,             -- 0=unchanged, 1=rotated (value changed)
            rotation_detected_at TEXT,
            status TEXT DEFAULT 'active'            -- active|rotated|false_positive
        );
        CREATE TABLE IF NOT EXISTS secret_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            prev_fingerprint TEXT,                  -- fingerprint of previous value (for rotation tracking)
            next_fingerprint TEXT,                  -- fingerprint of next value (for rotation tracking)
            seen_at TEXT NOT NULL,
            FOREIGN KEY (fingerprint) REFERENCES secret_fingerprints(fingerprint)
        );
        CREATE INDEX IF NOT EXISTS idx_sightings_repo ON secret_sightings(repo_path);
        CREATE INDEX IF NOT EXISTS idx_sightings_fp ON secret_sightings(fingerprint);
    """)
    return conn


# ── Secret extraction ─────────────────────────────────────
def _extract_secrets(repo: Path) -> List[dict]:
    """Extract secret-like strings from a repo. Fingerprint only — no values stored."""
    findings = []

    # Patterns for common secret formats (without capturing values)
    patterns = [
        # API keys (40-char hex)
        (r'[A-Za-z0-9+/=]{40,}', 'api_key'),
        # AWS keys (AKIA...)
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
        # Private keys (BEGIN...END)
        (r'-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PRIVATE)\s+KEY-----', 'private_key'),
        # JWT tokens
        (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'jwt_token'),
        # Passwords in config
        (r'(?:password|passwd|pwd|secret|token)\s*[:=]\s*[\'"]?([^\s\'"]{8,})', 'config_secret'),
        # Database URLs
        (r'(?:mongodb|mysql|postgresql|redis)://[^\s]{10,}', 'db_url'),
        # Generic hex strings (potential keys)
        (r'\b[0-9a-fA-F]{32,64}\b', 'hex_key'),
    ]

    import re
    exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
            ".yaml", ".yml", ".json", ".env", ".toml", ".sh", ".bash",
            ".cfg", ".ini", ".conf", ".xml", ".properties", ".tf"}

    for f in repo.rglob("*"):
        if f.suffix not in exts or f.name.startswith("."):
            continue
        if any(d in str(f) for d in [".git", "node_modules", "__pycache__",
                                       "venv", ".venv", "dist", "build"]):
            continue

        try:
            content = f.read_text()
            for i, line in enumerate(content.split("\n"), 1):
                for pat, kind in patterns:
                    for m in re.finditer(pat, line, re.IGNORECASE):
                        value = m.group(0)
                        # Hash the value — store fingerprint ONLY
                        fp = hashlib.sha256(value.encode()).hexdigest()[:32]

                        # Skip obvious false positives
                        if len(value) < 8:
                            continue
                        if value.startswith(("http://", "https://", "file://")):
                            continue
                        # Skip common placeholders
                        if any(p in value.lower() for p in
                               ["example", "placeholder", "changeme", "xxxx",
                                "dummy", "test", "your-", "$"]):
                            continue

                        findings.append({
                            "fingerprint": fp,
                            "repo": str(repo),
                            "file": str(f.relative_to(repo)),
                            "line": i,
                            "kind": kind,
                            "length": len(value),
                        })
        except Exception:
            pass

    return findings


# ── Correlation engine ────────────────────────────────────
def correlate(repos: List[str]) -> Dict:
    """Scan repos and correlate secret fingerprints across them."""
    conn = _connect()

    all_findings = []
    for repo_path in repos:
        repo = Path(repo_path)
        if not repo.exists():
            print(f"⚠️ {repo_path}: not found, skipping")
            continue

        print(f"🔍 Scanning {repo.name}...")
        findings = _extract_secrets(repo)
        all_findings.extend(findings)
        print(f"   {len(findings)} secrets extracted")

    if not all_findings:
        return {"error": "No secrets found", "correlations": []}

    # Group by fingerprint
    by_fp = defaultdict(list)
    for f_ in all_findings:
        by_fp[f_["fingerprint"]].append(f_)

    # Correlate: same fingerprint in multiple repos
    cross_repo = []
    now = datetime.now(timezone.utc).isoformat()

    for fp, sightings in sorted(by_fp.items(), key=lambda x: -len(x[1])):
        repos_seen = set(s["repo"] for s in sightings)
        if len(repos_seen) < 2:
            continue  # Skip single-repo secrets

        # Upsert fingerprint
        existing = conn.execute(
            "SELECT * FROM secret_fingerprints WHERE fingerprint = ?", (fp,)
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE secret_fingerprints SET last_seen=?, repo_count=?, total_sightings=total_sightings+? WHERE fingerprint=?",
                (now, len(repos_seen), len(sightings), fp),
            )
        else:
            conn.execute(
                "INSERT INTO secret_fingerprints (fingerprint, first_seen, last_seen, repo_count, total_sightings) VALUES (?,?,?,?,?)",
                (fp, now, now, len(repos_seen), len(sightings)),
            )

        # Record sightings
        for s in sightings:
            conn.execute(
                "INSERT INTO secret_sightings (fingerprint, repo_path, file_path, line_number, seen_at) VALUES (?,?,?,?,?)",
                (fp, s["repo"], s["file"], s["line"], now),
            )

        cross_repo.append({
            "fingerprint": fp,
            "repos": len(repos_seen),
            "sightings": len(sightings),
            "kind": sightings[0]["kind"],
            "files": [s["file"] for s in sightings[:5]],
        })

    conn.commit()

    # Also detect rotations — fingerprints that were replaced
    _detect_rotations(conn)

    conn.close()

    return {
        "scanned_repos": len(repos),
        "total_secrets": len(all_findings),
        "cross_repo_secrets": len(cross_repo),
        "correlations": cross_repo[:20],
    }


def _detect_rotations(conn: sqlite3.Connection) -> None:
    """Detect secret rotation: same file, same line, different fingerprint over time."""
    rows = conn.execute("""
        SELECT a.fingerprint AS fp_a, b.fingerprint AS fp_b,
               a.repo_path, a.file_path, a.line_number,
               a.seen_at AS prev_date, b.seen_at AS next_date
        FROM secret_sightings a
        JOIN secret_sightings b ON a.repo_path = b.repo_path
            AND a.file_path = b.file_path
            AND a.line_number = b.line_number
            AND a.fingerprint != b.fingerprint
            AND a.seen_at < b.seen_at
        LIMIT 50
    """).fetchall()

    for row in rows:
        conn.execute(
            "UPDATE secret_fingerprints SET rotated=1, rotation_detected_at=? WHERE fingerprint=?",
            (row["prev_date"], row["fp_a"]),
        )
        conn.execute(
            "UPDATE secret_sightings SET next_fingerprint=? WHERE fingerprint=? AND seen_at=?",
            (row["fp_b"], row["fp_a"], row["prev_date"]),
        )
        conn.execute(
            "UPDATE secret_sightings SET prev_fingerprint=? WHERE fingerprint=? AND seen_at=?",
            (row["fp_a"], row["fp_b"], row["next_date"]),
        )


def secret_status(fingerprint: str) -> Dict:
    """Get detailed status for a specific secret fingerprint."""
    conn = _connect()
    fp_row = conn.execute(
        "SELECT * FROM secret_fingerprints WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()

    if not fp_row:
        conn.close()
        return {"error": f"Fingerprint {fingerprint} not found"}

    sightings = conn.execute(
        "SELECT * FROM secret_sightings WHERE fingerprint = ? ORDER BY seen_at DESC",
        (fingerprint,),
    ).fetchall()
    conn.close()

    return {
        "fingerprint": fingerprint,
        "status": fp_row["status"],
        "rotated": bool(fp_row["rotated"]),
        "first_seen": fp_row["first_seen"],
        "last_seen": fp_row["last_seen"],
        "repos": fp_row["repo_count"],
        "total_sightings": fp_row["total_sightings"],
        "sightings": [{
            "repo": s["repo_path"],
            "file": s["file_path"],
            "line": s["line_number"],
            "seen_at": s["seen_at"],
        } for s in sightings[:20]],
    }


def secret_report() -> Dict:
    """Generate cross-repo secrets report."""
    conn = _connect()

    total = conn.execute("SELECT COUNT(*) as c FROM secret_fingerprints").fetchone()["c"]
    cross = conn.execute(
        "SELECT COUNT(*) as c FROM secret_fingerprints WHERE repo_count > 1"
    ).fetchone()["c"]
    rotated = conn.execute(
        "SELECT COUNT(*) as c FROM secret_fingerprints WHERE rotated = 1"
    ).fetchone()["c"]

    top = conn.execute("""
        SELECT fingerprint, repo_count, total_sightings, rotated, first_seen
        FROM secret_fingerprints
        WHERE repo_count > 1
        ORDER BY repo_count DESC, total_sightings DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    return {
        "total_secrets": total,
        "cross_repo": cross,
        "rotated": rotated,
        "risk_score": "high" if cross > 10 else "medium" if cross > 3 else "low",
        "top_correlated": [dict(r) for r in top],
    }


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Cross-Repo Secret Correlation")
    sub = p.add_subparsers(dest="cmd", required=True)

    corr = sub.add_parser("correlate", help="Scan repos and correlate secrets")
    corr.add_argument("--repos", nargs="+", required=True, help="Repository paths")
    corr.add_argument("--output", "-o", help="Save JSON")

    st = sub.add_parser("status", help="Detailed status of a secret")
    st.add_argument("--key", required=True, help="Secret fingerprint")

    rep = sub.add_parser("report", help="Cross-repo secrets report")
    rep.add_argument("--output", "-o", help="Save JSON")

    args = p.parse_args()

    if args.cmd == "correlate":
        result = correlate(args.repos)
        print(f"\n{'='*50}")
        print(f"Cross-Repo Secrets: {result['cross_repo_secrets']} secrets in ≥2 repos")
        for c in result.get("correlations", [])[:10]:
            print(f"  {c['fingerprint'][:12]}... — {c['repos']} repos, {c['sightings']} sightings, kind={c['kind']}")
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.cmd == "status":
        result = secret_status(args.key)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.cmd == "report":
        result = secret_report()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
