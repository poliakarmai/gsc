#!/usr/bin/env python3
"""GSC TP Seed — mark confirmed vulnerability findings as True Positives."""
import sqlite3, os, hashlib, json
from datetime import datetime, timezone

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

# Confirmed vulnerabilities from our PRs (manual annotation based on merged/accepted PRs)
TP_SEEDS = [
    {
        "project": "aio-libs/aiohttp-security",
        "pr": "#1005",
        "cwe": "CWE-384",
        "title": "Session fixation — regenerate session on login",
        "file_path": "demo/database_auth/handlers.py",
        "pattern": "GS019",
        "category": "HIGH",
        "detail": "Session ID not regenerated after authentication, enabling session fixation attack",
    },
    {
        "project": "mathiasertl/django-ca",
        "pr": "#202",
        "cwe": "CWE-918",
        "title": "SSRF in ACME HTTP-01 challenge validation",
        "file_path": "ca/ca/acme/validation.py",
        "pattern": "GS021",
        "category": "CRITICAL",
        "detail": "URL validation bypass allows SSRF via ACME HTTP-01 challenge",
    },
    {
        "project": "stanfrbd/cyberbro",
        "pr": "#212",
        "cwe": "CWE-79",
        "title": "XSS via innerHTML in search highlight",
        "file_path": "engines/spur_us.py",
        "pattern": "GS020",
        "category": "HIGH",
        "detail": "innerHTML used with unsanitized user input in search results",
    },
    {
        "project": "deep-learning-indaba/Baobab",
        "pr": "#1401",
        "cwe": "CWE-798",
        "title": "Hardcoded API key in source code",
        "file_path": "baobab/baobab/config.py",
        "pattern": "GS001",
        "category": "CRITICAL",
        "detail": "Hardcoded API key found in configuration file",
    },
    {
        "project": "manjurulhoque/doccure",
        "pr": "#14",
        "cwe": "CWE-798",
        "title": "Hardcoded SECRET_KEY in settings",
        "file_path": "Doctor/appointment/views.py",
        "pattern": "GS001",
        "category": "CRITICAL",
        "detail": "SECRET_KEY moved to environment variables (CWE-798)",
    },
]


def seed():
    from gsc_core.gsc_db import compute_finding_key
    db = sqlite3.connect(DB)
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0

    for seed in TP_SEEDS:
        fp = hashlib.sha256(
            f"{seed['pattern']}|{seed['title']}|{seed['file_path']}|{seed['detail'][:100]}".encode()
        ).hexdigest()[:16]

        # Check if already seeded
        existing = db.execute(
            "SELECT id FROM findings WHERE project=? AND file_path=? AND detail LIKE ?",
            (seed["project"], seed["file_path"], f"%{seed['detail'][:30]}%"),
        ).fetchone()

        if existing:
            db.execute(
                """UPDATE findings 
                   SET status='confirmed', revalidation_verdict='TP', 
                       revalidation_checked_at=?, revalidation_reasoning=?,
                       pattern_id=?
                   WHERE id=?""",
                (now, f"TP seed from {seed['pr']} ({seed['cwe']})", fp, existing[0]),
            )
            print(f"  ✅ UPDATED {seed['project']}{seed['pr']} → TP")
        else:
            db.execute(
                """INSERT OR IGNORE INTO findings 
                   (project, category, title, file_path, detail, pattern_id,
                    status, revalidation_verdict, revalidation_checked_at, 
                    revalidation_reasoning, echelon, noise_tier, created_at, rule_id, finding_key)
                   VALUES (?, ?, ?, ?, ?, ?, 'confirmed', 'TP', ?, ?, 2, 'seed', ?, ?, ?)""",
                (
                    seed["project"], seed["category"], seed["title"],
                    seed["file_path"], seed["detail"], fp,
                    now, f"TP seed from {seed['pr']} ({seed['cwe']})",
                    now,
                    seed.get("pattern"),
                    compute_finding_key(seed.get("pattern"), seed["file_path"], seed["detail"]),
                ),
            )
            print(f"  ✅ INSERTED {seed['project']}{seed['pr']} → TP")
        inserted += 1

    db.commit()
    
    # Show new TP count
    tp_count = db.execute("SELECT COUNT(*) FROM findings WHERE revalidation_verdict='TP'").fetchone()[0]
    fp_count = db.execute("SELECT COUNT(*) FROM findings WHERE revalidation_verdict='FP'").fetchone()[0]
    print(f"\nDone. TP: {tp_count}, FP: {fp_count}")
    db.close()


if __name__ == "__main__":
    seed()
