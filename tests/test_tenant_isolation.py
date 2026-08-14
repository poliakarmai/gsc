"""tests/test_tenant_isolation.py — due-diligence шаг 4: two-tenant isolation.

Exit criterion аудита: «no cross-tenant read/write; signup/invite behavior
matches public docs». Проверяем, что tenant-scoped доступ (WHERE tenant_id) не
позволяет одному тенанту читать/менять/удалять данные другого.
"""
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_db_backend import SqliteBackend


def _schema(db: SqliteBackend) -> None:
    db.executescript("""
        CREATE TABLE tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, github_user TEXT,
            plan TEXT DEFAULT 'free', scans_used INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER,
            key_hash TEXT UNIQUE, key_prefix TEXT, created_at TEXT, revoked_at TEXT);
        CREATE TABLE findings (
            finding_key TEXT, rule_id TEXT, title TEXT, severity TEXT DEFAULT 'UNKNOWN',
            confidence REAL, file TEXT, line INTEGER, snippet TEXT, tenant_id INTEGER,
            created_at TEXT, PRIMARY KEY (tenant_id, finding_key));
    """)


def test_cross_tenant_read_blocked(tmp_path):
    db = SqliteBackend(str(tmp_path / "t.db"))
    _schema(db)
    t1 = db.insert_id("INSERT INTO tenants (name) VALUES ('acme') RETURNING id")
    t2 = db.insert_id("INSERT INTO tenants (name) VALUES ('globex') RETURNING id")
    db.execute("INSERT INTO findings (finding_key,rule_id,title,tenant_id) VALUES ('k1','GS005','XSS',?)", (t1,))

    assert len(db.query("SELECT * FROM findings WHERE tenant_id=?", (t1,))) == 1
    assert len(db.query("SELECT * FROM findings WHERE tenant_id=?", (t2,))) == 0


def test_cross_tenant_write_blocked(tmp_path):
    db = SqliteBackend(str(tmp_path / "t.db"))
    _schema(db)
    t1 = db.insert_id("INSERT INTO tenants (name) VALUES ('a') RETURNING id")
    t2 = db.insert_id("INSERT INTO tenants (name) VALUES ('b') RETURNING id")
    db.execute("INSERT INTO findings (finding_key,rule_id,title,tenant_id) VALUES ('k1','GS005','XSS',?)", (t1,))

    # UPDATE с tenant predicate не задевает чужой tenant
    rc = db.execute("UPDATE findings SET severity='CRITICAL' WHERE tenant_id=? AND finding_key='k1'", (t2,))
    assert rc == 0
    row = db.fetchone("SELECT severity FROM findings WHERE tenant_id=? AND finding_key='k1'", (t1,))
    assert row["severity"] == "UNKNOWN"  # не изменён tenant B (остался default)

    # DELETE с tenant predicate тоже
    rc = db.execute("DELETE FROM findings WHERE tenant_id=? AND finding_key='k1'", (t2,))
    assert rc == 0
    assert len(db.query("SELECT * FROM findings WHERE tenant_id=?", (t1,))) == 1


def test_signup_invite_only_matches_docs(tmp_path):
    """GSC-007/шаг 4: при GSC_INVITE_ONLY=1 signup отклоняется (fail-closed)."""
    repo = str(Path(__file__).parent.parent)
    code = (
        "import os\n"
        f"os.environ['GSC_DB'] = {str(tmp_path / 'c.db')!r}\n"
        "os.environ['GSC_INVITE_ONLY'] = '1'\n"
        "os.environ['GSC_DEV_MODE'] = '1'\n"  # иначе JWT fail-closed exit (roadmap 3.8)
        "import server\n"
        "from fastapi.testclient import TestClient\n"
        "r = TestClient(server.app).post('/api/v2/auth/signup', params={'github_user': 'x'})\n"
        "print(r.status_code)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=repo)
    assert "403" in r.stdout, f"expected 403, stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
