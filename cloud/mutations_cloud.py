"""Инжест отчёта в PG с использованием ИСТОРИИ тенанта (S2).

Мутации и авто-resolve живут здесь, а не в эфемерном SQLite worker'а:
история должна переживать контейнер.
"""
from __future__ import annotations

import json
import os

from gsc_db_backend import PgBackend
from gsc_mutation_tracker import (MutationMatcher, fingerprint,
                                  normalize_snippet)

LOOKBACK_DAYS = 90
MIN_CONFIDENCE = 0.55
MAX_PARENTS = 20


def ingest_with_history(job: dict, report: dict) -> None:
    tenant_id = job["tenant_id"]
    db = PgBackend(os.environ["GSC_DATABASE_URL"], tenant_id)
    scan_id = job["scan_id"]
    matcher = MutationMatcher()

    current_keys = set()
    for f in report.get("findings", []):
        snippet = f.get("snippet", "")
        norm = normalize_snippet(snippet)
        fp = fingerprint(snippet)
        current_keys.add(f["finding_key"])
        db.execute("""
            INSERT INTO findings
                (tenant_id, scan_id, finding_key, rule_id, severity,
                 confidence, file, line, snippet, poc, metadata,
                 pattern_fingerprint, normalized_snippet)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tenant_id, scan_id, f["finding_key"], f["rule_id"],
              f.get("severity"), f.get("confidence"), f.get("file"),
              f.get("line"), snippet,
              (f.get("metadata") or {}).get("poc", ""),
              json.dumps(f.get("metadata") or {}), fp, norm))

        # Мутации: только full-сканы, only likely+, только resolved-родители
        if (not job["pr"].get("is_fork")
                and f.get("confidence", 0) >= MIN_CONFIDENCE and fp):
            parents = db.query("""
                SELECT finding_key, file, snippet, normalized_snippet,
                       resolved_at
                FROM findings
                WHERE tenant_id = ? AND rule_id = ?
                  AND resolved_at IS NOT NULL
                  AND resolved_at > now() - make_interval(days => ?)
                ORDER BY resolved_at DESC LIMIT ?
            """, (tenant_id, f["rule_id"], LOOKBACK_DAYS, MAX_PARENTS))
            alert = matcher.match(f, norm, parents)
            if alert:
                db.execute("""
                    INSERT INTO mutation_alerts
                        (tenant_id, finding_key, parent_key, kind, similarity)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, finding_key, parent_key)
                    DO NOTHING
                """, (tenant_id, alert.finding_key, alert.parent_key,
                      alert.kind, alert.similarity))

    # Цепочки из отчёта
    for c in report.get("chains", []):
        db.execute("""
            INSERT INTO chains
                (tenant_id, chain_key, finding_keys, composed_severity,
                 confidence, narrative)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, chain_key) DO UPDATE SET
                confidence = excluded.confidence,
                narrative = excluded.narrative
        """, (tenant_id, c["chain_key"], json.dumps(c["finding_keys"]),
              c["composed_severity"], c["confidence"], c.get("narrative")))

    db.commit()