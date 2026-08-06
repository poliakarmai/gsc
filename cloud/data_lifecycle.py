"""Retention и удаление данных тенанта (техническое обеспечение DPA).

Политика:
  - артефакты сканов (отчёты в объектном хранилище): 90 дней
  - findings/chains/mutations: срок жизни тенанта
  - audit_events: 7 лет (SOC 2) — НЕ удаляются retention'ом
  - billing-события (stripe_events): 7 лет (налоговые споры)
  - удаление тенанта: заявка → 30 дней grace → каскад
"""
from __future__ import annotations

from cloud import audit

TENANT_TABLES = [
    # порядок = зависимости: сначала дети, потом родители
    "verdicts", "mutation_alerts", "overrides", "chains",
    "findings", "published_comments", "publication_events",
    "comment_reactions", "data_deletion_requests", "audit_events",
    "scans", "repos", "memberships", "github_installs", "usage",
    "api_keys", "tenants",
]


def request_deletion(db, tenant_id: int, actor: str,
                     reason: str = "") -> None:
    db.execute("""
        INSERT INTO data_deletion_requests
            (tenant_id, requested_by, reason, execute_at)
        VALUES (?, ?, ?, now() + interval '30 days')
    """, (tenant_id, actor, reason[:500]))
    audit.record(db, tenant_id, actor, "data.deletion_requested",
                 "tenant", str(tenant_id), {"grace_days": 30})
    db.commit()


def execute_due_deletions(db_admin) -> list[int]:
    """Запускается nightly. Возвращает список удалённых тенантов."""
    due = db_admin.query("""
        SELECT id, tenant_id FROM data_deletion_requests
        WHERE status = 'pending' AND execute_at <= now()
        ORDER BY execute_at
    """)
    done = []
    for row in due:
        tid = row["tenant_id"]
        for table in TENANT_TABLES:
            db_admin.execute(
                f"DELETE FROM {table} WHERE tenant_id = ?", (tid,))
        db_admin.execute("""
            UPDATE data_deletion_requests
            SET status = 'completed', completed_at = now()
            WHERE id = ?
        """, (row["id"],))
        done.append(tid)
    db_admin.commit()
    return done