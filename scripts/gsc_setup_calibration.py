#!/usr/bin/env python3
"""Create minimal calibration projects for verification."""
from pathlib import Path

CALIB = Path("/tmp/gsc-calibration")

VULN = {
    "sqli-demo": ("py", 'def q(x):\n    return db.execute(f"SELECT * FROM u WHERE id={x}")\n', "GS005"),
    "xss-demo": ("py", 'def render(name):\n    return f"<div>{name}</div>"\n', "GS020"),
    "secrets-demo": ("py", 'password = "SuperSecret123!"\napi_key = "sk_live_abcdef"\n', "GS029"),
    "eval-demo": ("py", 'def exec(u): return eval(u)\n', "GS008"),
    "pickle-demo": ("py", 'import pickle\ndef load(x): return pickle.loads(x)\n', "GS004"),
    "bare-except-demo": ("py", 'try:\n    risky()\nexcept:\n    pass\n', "GS003"),
    "assert-demo": ("py", 'def validate(x):\n    assert x > 0\n    return x\n', "GS015"),
    "hardcoded-secret": ("py", 'API_TOKEN="ghp_abcdef123456"\nsecret="mysecret"\n', "GS029"),
    "iac-demo": ("dockerfile", 'FROM node:latest\nUSER root\nENV SECRET=x\n', "GS031"),
}

CLEAN = {
    "clean-pure": ("py", 'def add(a: int, b: int) -> int:\n    return a + b\n'),
}

def setup():
    CALIB.mkdir(parents=True, exist_ok=True)
    for name, (lang, code, rule) in VULN.items():
        d = CALIB / name; d.mkdir(exist_ok=True)
        ext = "Dockerfile" if lang == "dockerfile" else "app.py"
        (d / ext).write_text(code)
        (d / "expected.json").write_text(f'{{"findings": [{{"rule_id": "{rule}"}}]}}')
        print(f"  ✅ {name} → {rule}")
    for name, (lang, code) in CLEAN.items():
        d = CALIB / name; d.mkdir(exist_ok=True)
        (d / "app.py").write_text(code)
        (d / "expected.json").write_text('{"findings": []}')
        print(f"  ✅ {name} (clean)")
    print(f"\nProjects in {CALIB}")

if __name__ == "__main__":
    setup()
