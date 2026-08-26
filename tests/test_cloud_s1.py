#!/usr/bin/env python3
"""tests/test_cloud_s1.py — SaaS S1: multi-tenant isolation (v1.1)."""
import sys, os, sqlite3
os.chdir(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, '.')

passed, failed = 0, 0
def t(name, fn):
    global passed, failed
    try: fn(); print(f'  PASS {name}'); passed += 1
    except Exception as e: print(f'  FAIL {name}: {e}'); failed += 1

def fresh_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE schema_version (version INT)")
    db.execute("INSERT INTO schema_version VALUES (28)")
    db.execute("CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, created_at TEXT DEFAULT (datetime('now')))")
    db.execute("CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER REFERENCES tenants(id), key_hash TEXT UNIQUE, key_prefix TEXT, created_at TEXT DEFAULT (datetime('now')), revoked_at TEXT)")
    db.execute("CREATE TABLE findings (finding_key TEXT PRIMARY KEY, rule_id TEXT, title TEXT, severity TEXT, confidence REAL, file TEXT, line INT, snippet TEXT, tenant_id INTEGER)")
    db.execute("INSERT INTO tenants (name) VALUES ('acme')")
    return db

def t1():
    from gsc_cloud.auth import generate_api_key
    raw, h = generate_api_key()
    assert raw.startswith("gsk_") and len(h) == 64
t('api key generation', t1)

def t2():
    import hashlib
    db = fresh_db()
    raw = "gsk_test100"
    h = hashlib.sha256(raw.encode()).hexdigest()
    # Canonical: key_prefix mirrors server.py key minting (raw[:8]).
    db.execute("INSERT INTO api_keys (tenant_id,key_hash,key_prefix) VALUES (1,?,?)", (h, raw[:8]))
    db.commit()
    # Mock DB interface compatible with gsc_cloud.auth.verify_api_key
    class D: pass
    d = D()
    def _q(s, p):
        cur = db.execute(s, p)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    d.query = _q
    from gsc_cloud.auth import verify_api_key
    assert verify_api_key(raw, d) == 1
    assert verify_api_key("gsk_bad", d) is None
t('verify api key resolves tenant', t2)

def t3():
    db = fresh_db()
    db.execute("INSERT INTO findings (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id) VALUES ('a','GS005','Test','HIGH',0.9,'f.py',1,'x',1)")
    db.execute("INSERT INTO findings (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id) VALUES ('b','GS005','Test2','HIGH',0.9,'f.py',1,'x',2)")
    db.commit()
    class D: pass
    d = D(); d.query = lambda s,p: [dict(zip([c[0] for c in db.execute(s,p).description], row)) for row in db.execute(s,p).fetchall()]
    from gsc_cloud.auth import scoped_query
    sql, params = scoped_query("SELECT * FROM findings", 1)
    rows = d.query(sql, params)
    assert len(rows) == 1 and rows[0]["tenant_id"] == 1
t('scoped query tenant isolation', t3)

def t4():
    db = fresh_db()
    import hashlib
    raw = "gsk_test100"
    h = hashlib.sha256(raw.encode()).hexdigest()
    db.execute("INSERT INTO api_keys (tenant_id,key_hash,key_prefix,revoked_at) VALUES (1,?,?,datetime('now'))", (h, raw[:8]))
    db.commit()
    class D: pass
    d = D()
    def _q(s, p):
        cur = db.execute(s, p)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    d.query = _q
    from gsc_cloud.auth import verify_api_key
    assert verify_api_key(raw, d) is None
t('revoked key rejected', t4)

def t5():
    db = fresh_db()
    class D: pass
    d = D(); d.query = lambda s, p: []
    from gsc_cloud.api_v2 import handle_scan_v2
    _, status = handle_scan_v2(d, "gsk_bad", "./repo", "audit")
    assert status == 401
t('scan v2 unauthorized', t5)

print(f'\n{"="*50}\nResults: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
