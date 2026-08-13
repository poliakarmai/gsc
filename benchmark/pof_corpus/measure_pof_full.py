#!/usr/bin/env python3
"""Полный PoF-цикл GSC на сертифицированном корпусе.

Для каждого vuln-приложения: scan → detect (TP) → PoC (ground-truth, адаптирован
под TARGET_URL) → sandbox _execute (vulnerable должен EXPLOIT, patched должен FAIL).

PoF verified = before.success AND NOT after.success (полный цикл D→P→V через GSC sandbox).

Запуск: python3 measure_pof_full.py [--app id]
"""
import json, re, subprocess, sys
from pathlib import Path
from urllib.parse import quote

CORPUS = Path(__file__).resolve().parent
GSC = Path.home() / "gsc" / "gsc.py"
PY = sys.executable

sys.path.insert(0, str(Path.home() / "gsc"))


def scan(app_dir) -> list:
    r = subprocess.run([PY, str(GSC), "scan", str(app_dir), "--ci", "--json"],
                       capture_output=True, text=True, timeout=300)
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    return d if isinstance(d, list) else d.get("findings", [])


def detect(findings, app):
    if app.get("clean"):
        crit = [f for f in findings if f.get("category") in ("CRITICAL", "HIGH")]
        return ("FP" if crit else "TN"), None, None
    exp = app["expected_rule_id"]
    for f in findings:
        rid = f.get("rule_id") or ""
        if rid.startswith(exp) and "app.py" in (f.get("file_path") or ""):
            return "TP", f, rid
    for f in findings:
        if f.get("category") in ("CRITICAL", "HIGH") and "app.py" in (f.get("file_path") or ""):
            return "MISLABELED", f, f.get("rule_id")
    return "FN", None, None


def build_poc(meta, app_dir):
    """Превращает ground-truth PoC в формат sandbox (TARGET_URL + SUCCESS_MARKER)."""
    poc_name = "poc.py" if meta.get("poc_format") == "python" else "poc.sh"
    raw = (app_dir / poc_name).read_text()

    if meta.get("poc_format") == "python":
        # deser: bash-версия с pickle payload (sandbox _execute_shell заменяет TARGET_URL)
        return (
            'PAYLOAD=$(python3 -c "import base64,pickle;'
            'print(base64.b64encode(pickle.dumps(type(\'E\',(),{\'__reduce__\':'
            'lambda s:(str,(\'DESER_PWNED\',))})())).decode())")\n'
            'curl -s -X POST "TARGET_URL/load" -d "$PAYLOAD" | grep -q "DESER_PWNED" '
            '&& echo EXPLOITED || echo NOT_EXPLOITED\n'
        ), "curl"

    # bash: заменить $BASE / http://127.0.0.1:${PORT...} → TARGET_URL
    poc = re.sub(r'http://127\.0\.0\.1:\$\{PORT[^}]*\}', 'TARGET_URL', raw)
    poc = poc.replace('"$BASE', '"TARGET_URL')
    return poc, "curl"


def run_sandbox(poc_code, fmt, project_dir):
    from gsc_pof_sandbox import PoFSandbox
    sb = PoFSandbox()
    target_code = ""  # для curl-PoC с project_dir сервер поднимается из project_dir
    res = sb._execute(poc_code, target_code, fmt=fmt, project_dir=project_dir)
    return res.success


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    apps = [a for a in manifest["apps"] if not a.get("clean")]
    only = None
    if "--app" in sys.argv:
        only = sys.argv[sys.argv.index("--app") + 1]
        apps = [a for a in apps if a["id"] == only]

    rows = []
    for app in apps:
        vuln_dir = CORPUS / app["vulnerable_dir"]
        patched_dir = CORPUS / app["patched_dir"] if app.get("patched_dir") else None
        app_dir = vuln_dir.parent
        meta = json.loads((app_dir / "meta.json").read_text())

        findings = scan(vuln_dir)
        status, finding, actual = detect(findings, app)

        row = {"id": app["id"], "class": app["class"], "detect": status,
               "expected": app.get("expected_rule_id"), "actual": actual}

        if status in ("TP", "MISLABELED") and patched_dir:
            poc_code, fmt = build_poc(meta, app_dir)
            try:
                before = run_sandbox(poc_code, fmt, str(vuln_dir))
                after = run_sandbox(poc_code, fmt, str(patched_dir))
                row["before_exploited"] = before
                row["after_still_exploited"] = after
                row["pof_verified"] = bool(before and not after)
            except Exception as e:
                row["pof_verified"] = False
                row["error"] = str(e)[:120]

        rows.append(row)
        if status in ("TP", "MISLABELED"):
            print(f"{status:10} {app['id']:22} before_exploited={row.get('before_exploited')} "
                  f"after_exploited={row.get('after_still_exploited')} "
                  f"PoF={'✅' if row.get('pof_verified') else '❌'}"
                  + (f" err={row['error']}" if row.get('error') else ''))
        else:
            print(f"{status:10} {app['id']:22} (не найдено — PoF неприменим)")

    report(rows)


def report(rows):
    print("\n" + "=" * 62)
    det = [r for r in rows if r["detect"] in ("TP", "MISLABELED")]
    n_found = len(det)
    n_pof = sum(1 for r in rows if r.get("pof_verified"))
    print(f"Найдено (detect): {n_found}/{len(rows)}")
    print(f"PoF verified (полный цикл): {n_pof}/{len(rows)}  "
          f"({n_pof/n_found:.0%} от найденных)" if n_found else "PoF: 0 (ничего не найдено)")
    failed = [r for r in rows if r["detect"] in ("TP", "MISLABELED") and not r.get("pof_verified")]
    for r in failed:
        reason = "before не эксплуатирует" if r.get("before_exploited") is False \
            else ("after всё ещё эксплуатирует" if r.get("after_still_exploited") else r.get("error", "?"))
        print(f"  ⚠️ {r['id']}: {reason}")


if __name__ == "__main__":
    main()
