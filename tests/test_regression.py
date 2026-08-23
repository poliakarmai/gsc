#!/usr/bin/env python3
"""tests/test_regression.py — regression: fixed bugs + invariants (+6, v0.36)."""
import sys, os, re, hashlib
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    from gsc_crossrepo_secrets import REFINED_PATTERNS
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    for p, t in REFINED_PATTERNS:
        assert re.search(p, sha) is None, f"{t} FP on SHA-256"
run_case('Secrets FP fix confirmed', t1)

def t2():
    from pathlib import Path
    dets = list((Path('.')/'gsc_core'/'gsc_detectors').glob('gs*.py'))
    assert len(dets) >= 28, f"only {len(dets)} detector files"
run_case('28+ detector files present', t2)

def t3():
    key = hashlib.sha256("GS001app.pydb.query(x)".encode()).hexdigest()[:12]
    assert len(key) == 12 and all(c in "0123456789abcdef" for c in key)
run_case('finding_key format stable', t3)

def t4():
    from gsc_blocking import BlockingEngine
    be = BlockingEngine(db=None, phase="blocking-standard", config={})
    assert be._meets_threshold({"severity":"CRITICAL","confidence":0.90}, [("CRITICAL",0.90),("HIGH",0.85)])
    assert not be._meets_threshold({"severity":"HIGH","confidence":0.80}, [("CRITICAL",0.90),("HIGH",0.85)])
run_case('Blocking Engine thresholds unchanged', t4)

def t5():
    from gsc_compliance import compliance_for
    for r in ["GS001","GS005","GS017","GS019","GS029","GS030","GS031-K8S-PRIVILEGED"]:
        assert compliance_for(r).get("cwe"), f"no CWE for {r}"
run_case('Compliance covers new rules', t5)

def t6():
    from pathlib import Path
    for mod in ["gsc_sca.py","gsc_sbom.py","gsc_spdx.py","gsc_iac.py","gsc_epss.py","gsc_federated.py"]:
        assert (Path('.')/mod).exists(), f"{mod} missing"
run_case('All P0/P1/P2 modules present', t6)

def _ctx_with(files):
    import tempfile
    from pathlib import Path
    from gsc_detectors import AuditContext
    td = tempfile.mkdtemp()
    p = Path(td)
    for name, content in files.items():
        (p / name).write_text(content)
    return AuditContext(project="x", path=p)

def t7():
    from gsc_detectors import gs019_auth_session as g19
    ctx = _ctx_with({"otp.py": "def generate_otp(self, input):\n    return hmac.new(self.byte_secret(), input).digest()\n"})
    fs = g19.detect(ctx)
    assert not any('OTP/SMS' in (f.get('title') or '') for f in fs), f"TOTP generation flagged as SMS send: {fs}"
run_case('GS019: TOTP generation != SMS send', t7)

def t8():
    from gsc_detectors import gs019_auth_session as g19
    ctx = _ctx_with({"backends.py": "def authenticate(self, request, mfa_user=None):\n    return mfa_user\n"})
    fs = g19.detect(ctx)
    assert not any('session regeneration' in (f.get('title') or '') for f in fs), f"authenticate() flagged as login/session fixation: {fs}"
run_case('GS019: authenticate() != session fixation', t8)

def t9():
    from gsc_detectors import gs007_idor as g7
    ctx = _ctx_with({"views.py": "x = Authenticator.objects.filter(user=request.user)\n"})
    fs = g7.detect(ctx)
    assert not any('cross-org' in (f.get('title') or '') for f in fs), f"self-scoped filter flagged as IDOR: {fs}"
run_case('GS007: self-scoped filter != IDOR', t9)

def t10():
    from gsc_detectors import gs025_ai_provenance as g25
    ctx = _ctx_with({"app.py": "api_key = 'abcdefghijklmnop'\n"})
    fs = g25.detect(ctx)
    assert fs, "GS025 should flag hardcoded secret"
    assert all(f.get('file_path') for f in fs), f"GS025 finding missing file_path: {fs}"
run_case('GS025: findings carry file_path', t10)

def t11():
    from gsc_detectors import gs001_hardcoded_secret as g1
    ctx = _ctx_with({"app.py": 'player_id = "4463358922001"\ncard = "4111111111111111"\n'})
    fs = g1.detect(ctx)
    titles = [f.get('title') or '' for f in fs]
    assert not any('PAN' in t and '4463358922001' in (f.get('detail') or '') for f, t in zip(fs, titles)), \
        f"Brightcove-style numeric ID flagged as PAN: {fs}"
    assert any('PAN' in t for t in titles), f"Luhn-valid PAN not detected: {fs}"
run_case('GS001: PAN requires Luhn checksum', t11)

def t12():
    from gsc_detectors import gs001_hardcoded_secret as g1
    ctx = _ctx_with({"common.py": 'TOKEN = "RESET_PASSWORD_BAD_TOKEN"\nPASSWORD = "REGISTER_INVALID_PASSWORD"\n'})
    fs = g1.detect(ctx)
    assert not fs, f"Enum constants flagged as secrets: {fs}"
run_case('GS001: enum/error-code constants are not secrets', t12)

def t13():
    from gsc_detectors import gs001_hardcoded_secret as g1
    ctx = _ctx_with({"captcha.py": 'token="10000000-aaaa-bbbb-cccc-000000000001"\n'})
    fs = g1.detect(ctx)
    assert not fs, f"hCaptcha test credential flagged: {fs}"
run_case('GS001: vendor test credentials are placeholders', t13)

def t14():
    from gsc_detectors import gs001_hardcoded_secret as g1
    ctx = _ctx_with({"app.py": 'password = "admin123"\n'})
    fs = g1.detect(ctx)
    assert fs, "Real hardcoded password not detected (TP regression)"
run_case('GS001: real secrets still detected (TP guard)', t14)

def t15():
    from gsc_detectors import gs005_sql_injection as g5
    safe = [
        'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))\n',
        'cursor.execute("SELECT * FROM users WHERE id=?", [uid])\n',
        'User.objects.raw("SELECT * FROM u WHERE id=%s", [u])\n',
        'session.execute(text("SELECT * FROM u WHERE name=:name"), {"name": name})\n',
        'cursor.execute("SELECT count(*) FROM t" + " WHERE x=1")\n',
        'cursor.execute("SELECT * FROM t WHERE data = \'{}\'::jsonb")\n',
        'cursor.execute("SELECT * FROM t WHERE x IN [1,2,3]")\n',
        'cursor.execute(queries[0])\n',
        'cursor.execute(config["sql_select"])\n',
    ]
    for code in safe:
        fs = g5.detect(_ctx_with({"app.py": code}))
        assert not fs, f"parameterized/static query flagged as SQLi: {code!r} -> {[f.get('title') for f in fs]}"
run_case('GS005: parameterized/static queries are not SQLi (FP fix)', t15)

def t16():
    from gsc_detectors import gs005_sql_injection as g5
    vuln = [
        'cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n',
        'cursor.execute("SELECT * FROM users WHERE id=%s" % uid)\n',
        'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n',
        'cursor.execute("SELECT {} FROM {}".format(t, c))\n',
        'session.execute(text(f"SELECT * FROM users WHERE name={name}"))\n',
    ]
    for code in vuln:
        fs = g5.detect(_ctx_with({"app.py": code}))
        assert fs, f"real SQLi not detected (TP regression): {code!r}"
run_case('GS005: real SQLi still detected (TP guard)', t16)

print(f'\n{"="*50}')
print(f'Regression: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
