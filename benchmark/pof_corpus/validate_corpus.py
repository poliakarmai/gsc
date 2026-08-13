#!/usr/bin/env python3
"""Сертификация PoF-корпуса: ground-truth PoC обязан эксплуатировать vulnerable/
и НЕ эксплуатировать patched/. Приложение валидно только если vuln_exploited ∧ patched_safe.

Запуск: python3 validate_corpus.py [--app sqli_01_search]   (без аргумента — все)
"""
import json, os, socket, subprocess, sys, time
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
PY = sys.executable


def find_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_app(app_dir, port, timeout=20):
    env = os.environ.copy()
    env["PORT"] = str(port)
    proc = subprocess.Popen([PY, "app.py"], cwd=app_dir, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return proc
        except OSError:
            if proc.poll() is not None:
                proc.kill()
                raise RuntimeError(f"app exited early: {app_dir}")
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"app did not start: {app_dir}")


def run_poc(poc_path, poc_format, port):
    env = {"PORT": str(port), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if poc_format == "python":
        r = subprocess.run([PY, str(poc_path)], env=env, capture_output=True, text=True, timeout=30)
    else:
        r = subprocess.run(["bash", str(poc_path)], env=env, capture_output=True, text=True, timeout=30)
    # NOT_EXPLOITED содержит подстроку EXPLOITED — проверяем точный маркер, не substring
    out = r.stdout.strip()
    return "NOT_EXPLOITED" not in out and "EXPLOITED" in out


def validate_app(app):
    base = CORPUS / app["vulnerable_dir"]
    app_dir = base.parent  # dir приложения (содержит vulnerable/, patched/, poc)
    # формат PoC из meta.json (а НЕ из manifest — там нет этого поля)
    meta_file = app_dir / "meta.json"
    poc_format = json.loads(meta_file.read_text()).get("poc_format", "bash") if meta_file.exists() else "bash"
    poc_name = "poc.py" if poc_format == "python" else "poc.sh"
    poc_path = app_dir / poc_name

    vuln_dir = CORPUS / app["vulnerable_dir"]
    pv = serve_app(vuln_dir, (port_v := find_free_port()))
    try:
        vuln_exploited = run_poc(poc_path, poc_format, port_v)
    finally:
        pv.kill()

    patched_safe = True
    patch_dir = app.get("patched_dir")
    if patch_dir:
        pp = serve_app(CORPUS / patch_dir, (port_p := find_free_port()))
        try:
            patched_safe = not run_poc(poc_path, poc_format, port_p)
        finally:
            pp.kill()

    return {"id": app["id"], "vuln_exploited": vuln_exploited,
            "patched_safe": patched_safe, "valid": vuln_exploited and patched_safe}


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    apps = [a for a in manifest["apps"] if not a.get("clean")]
    only = None
    if "--app" in sys.argv:
        only = sys.argv[sys.argv.index("--app") + 1]
        apps = [a for a in apps if a["id"] == only]

    report = []
    for a in apps:
        try:
            r = validate_app(a)
        except Exception as e:
            r = {"id": a["id"], "vuln_exploited": False, "patched_safe": False,
                 "valid": False, "error": str(e)[:120]}
        report.append(r)
        mark = "✅" if r.get("valid") else "❌"
        extra = f"  error={r.get('error')}" if r.get("error") else ""
        print(f"{mark} {r['id']:22} vuln_exploited={r['vuln_exploited']} "
              f"patched_safe={r['patched_safe']}{extra}")

    ok = sum(r.get("valid") for r in report)
    print(f"\nValid: {ok}/{len(report)}")
    sys.exit(0 if ok == len(report) else 1)


if __name__ == "__main__":
    main()
