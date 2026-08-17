#!/usr/bin/env python3
"""enterprise/tests/test_enterprise.py — RBAC, SSO, Audit, Compliance, Air-gap."""
import sys, os, importlib
os.chdir(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, '.')

from enterprise.rbac import can
from enterprise.sso import jit_provision, OIDCConfig
from enterprise.audit_log import AuditLog, GENESIS as G
from enterprise.compliance import map_finding, generate_report

p = f = 0
def t(name, fn):
    global p, f
    try: fn(); print(f'  ✅ {name}'); p += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); f += 1

def a1(): assert can("admin","manage_users"); assert not can("hacker","scan")
t('rbac admin all', a1)

def a2(): assert can("developer","verdict"); assert not can("developer","override")
t('rbac dev cannot override', a2)

def a3(): assert can("auditor","view_audit"); assert not can("auditor","verdict")
t('rbac auditor readonly', a3)

cfg = OIDCConfig()
def a4(): assert jit_provision({"sub":"u","email":"a@c","groups":["gsc-security"]}, cfg).role == "security_lead"
t('sso jit maps groups', a4)

def a5(): assert jit_provision({"sub":"u","groups":["random"]}, cfg).role == "readonly"
t('sso default role', a5)

class MockDB:
    def __init__(s): s.rows = []
    def execute(s, sql, p=()):
        if "INSERT" in sql:
            cols = ["ts","tenant_id","user_id","action","resource_type","resource_id","detail","prev_hash","entry_hash"]
            s.rows.append(dict(zip(cols[:len(p)], list(p)+[""]*9)))
    def fetchone(s, sql, p=()):
        r = [x for x in s.rows if x["tenant_id"]==p[0]]; return r[-1] if r else None
    def query(s, sql, p=()): return [x for x in s.rows if x["tenant_id"]==p[0]]

db = MockDB(); log = AuditLog(db)
log.record("t1","alice","scan"); log.record("t1","alice","verdict","finding","abc")
def a8(): assert log.verify_chain('t1')
t('audit chain integrity', a8)
def a9(): assert AuditLog(MockDB())._last_hash('x') == G
t('audit genesis', a9)

def a6(): assert "SOC2" in map_finding("GS001"); assert "PCI-DSS" in map_finding("GS001")
t('compliance mapping GS001', a6)

def a7(): assert generate_report([{"rule_id":"GS001","severity":"CRITICAL"}],"PCI-DSS")["total"]==1
t('compliance report', a7)

os.environ["GSC_AIRGAP"]="true"
def a10(): assert importlib.import_module('enterprise.airgap').is_airgap()
t('airgap detection', a10)

print(f'\n{"="*50}\nEnterprise: {p} passed, {f} failed')
if __name__ == "__main__":
    sys.exit(0 if f == 0 else 1)
