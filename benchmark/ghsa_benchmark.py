#!/usr/bin/env python3
"""Synthetic snippet benchmark for GSC — ground truth from known patterns.

Each pair: vulnerable code (MUST fire) + fixed code (MUST NOT fire).
Covers: GS005 SQLi, GS020 XSS, GS004 CmdInj, GS029 Secrets.
"""
import sys, json, time, tempfile
from pathlib import Path
from collections import defaultdict

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))

from gsc_detectors.registry import get_detectors
from gsc_detectors import AuditContext

# ── Ground truth: (rule_id, vulnerable_code, fixed_code, language) ──
GROUND_TRUTH = [
    # ═══ GS005 — SQL Injection ═══
    ("GS005", 'query = f"SELECT * FROM users WHERE id={uid}"\n', 
              'query = "SELECT * FROM users WHERE id=?"; cursor.execute(query, (uid,))\n', "python"),
    ("GS005", 'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n',
              'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))\n', "python"),
    ("GS005", 'db.execute(f"INSERT INTO logs VALUES (\'{msg}\')")\n',
              'db.execute("INSERT INTO logs VALUES (?)", (msg,))\n', "python"),
    ("GS005", 'conn.execute(f"DELETE FROM sessions WHERE token=\'{tok}\'")\n',
              'conn.execute("DELETE FROM sessions WHERE token=?", (tok,))\n', "python"),
    ("GS005", 'session.execute(text(f"SELECT * FROM users WHERE name=\'{name}\'"))\n',
              'session.execute(text("SELECT * FROM users WHERE name=:name"), {"name": name})\n', "python"),
    ("GS005", 'User.objects.raw(f"SELECT * FROM auth_user WHERE username=\'{u}\'")\n',
              'User.objects.filter(username=u)\n', "python"),
    ("GS005", 'var sql = "SELECT * FROM users WHERE id = " + userId;\n',
              'var sql = "SELECT * FROM users WHERE id = ?"; stmt.bind(userId);\n', "javascript"),
    ("GS005", 'const query = `SELECT * FROM products WHERE cat = ${category}`;\n',
              'const query = "SELECT * FROM products WHERE cat = ?"; db.all(query, [category]);\n', "javascript"),
    ("GS005", 'String sql = "SELECT * FROM users WHERE name=\'" + name + "\'";\n',
              'String sql = "SELECT * FROM users WHERE name=?"; PreparedStatement ps = conn.prepareStatement(sql);\n', "java"),
    # More Python SQLi patterns
    ("GS005", 'sql = "SELECT * FROM users WHERE id = %s" % user_id\n',
              'sql = "SELECT * FROM users WHERE id = %s"; cursor.execute(sql, (user_id,))\n', "python"),
    ("GS005", 'query = "SELECT * FROM users WHERE id={}".format(uid)\n',
              'query = "SELECT * FROM users WHERE id=?"; cursor.execute(query, (uid,))\n', "python"),
    ("GS005", 'User.objects.raw("SELECT * FROM users WHERE id = " + str(uid))\n',
              'User.objects.filter(id=uid)\n', "python"),
    ("GS005", 'cursor.execute("SELECT * FROM t WHERE x=" + str(x))\n',
              'cursor.execute("SELECT * FROM t WHERE x=?", (x,))\n', "python"),

    # ═══ GS020 — XSS ═══
    ("GS020", 'return f"<div>{name}</div>"\n',
              'from markupsafe import escape; return f"<div>{escape(name)}</div>"\n', "python"),
    ("GS020", 'response.write("<h1>" + title + "</h1>")\n',
              'from html import escape; response.write("<h1>" + escape(title) + "</h1>")\n', "python"),
    ("GS020", 'doc.innerHTML = "<p>" + userInput + "</p>";\n',
              'doc.textContent = userInput;\n', "javascript"),
    ("GS020", 'return "<span>" + name + "</span>";\n',
              'var div = document.createElement("span"); div.textContent = name;\n', "javascript"),
    ("GS020", '<div>{user_input}</div>\n',
              '<div>{{ user_input|escape }}</div>\n', "python"),

    # ═══ GS004 — Command Injection ═══
    ("GS004", 'os.system(f"ping {host}")\n',
              'subprocess.run(["ping", host], check=True)\n', "python"),
    ("GS004", 'subprocess.call("nslookup " + domain, shell=True)\n',
              'subprocess.call(["nslookup", domain])\n', "python"),
    ("GS004", 'os.popen("cat " + filename)\n',
              'with open(filename) as f: content = f.read()\n', "python"),
    ("GS004", 'child_process.exec("ls " + dir);\n',
              'child_process.execFile("ls", [dir]);\n', "javascript"),
    # Additional GS004 Java patterns
    ("GS004", 'Runtime.getRuntime().exec("cmd /c " + userInput);\n',
              'ProcessBuilder pb = new ProcessBuilder("cmd", "/c", userInput); pb.start();\n', "java"),

    # ═══ More GS005 — SQL Injection ═══
    ("GS005", 'q = "SELECT * FROM t WHERE x=" + request.args.get("x")\n',
              'q = "SELECT * FROM t WHERE x=?"; cursor.execute(q, (request.args.get("x"),))\n', "python"),
    ("GS005", 'sql = "SELECT * FROM users WHERE id = %d" % user_id\n',
              'sql = "SELECT * FROM users WHERE id = %s"; cursor.execute(sql, (user_id,))\n', "python"),
    ("GS005", 'db.execute("SELECT * FROM logs WHERE msg=\'" + msg + "\'")\n',
              'db.execute("SELECT * FROM logs WHERE msg=?", (msg,))\n', "python"),
    ("GS005", "const q = `SELECT * FROM items WHERE name = '${name}'`;\n",
              'const q = "SELECT * FROM items WHERE name = ?"; db.get(q, [name]);\n', "javascript"),

    # ═══ More GS020 — XSS ═══
    ("GS020", 'doc.write(\"<h2>\" + user + \"</h2>\");\n',
              'const h2 = document.createElement(\"h2\"); h2.textContent = user;\n', "javascript"),
    ("GS020", 'element.innerHTML = data;\n',
              'element.textContent = data;\n', "javascript"),

    # ═══ GS029 — Hardcoded Secrets ═══
    ("GS029", 'API_KEY = "sk-1234567890abcdef1234567890abcdef"\n',
              'API_KEY = os.environ.get("API_KEY")\n', "python"),
    ("GS029", 'password = "SuperSecret123!"\n',
              'password = os.environ.get("DB_PASSWORD")\n', "python"),
    ("GS029", 'const token = "ghp_1234567890abcdef1234567890abcdef1234";\n',
              'const token = process.env.GITHUB_TOKEN;\n', "javascript"),
    ("GS029", 'SECRET_KEY = "django-insecure-abc123def456"\n',
              'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n', "python"),

    # ═══ Clean (should NEVER fire for any detector) ═══
    ("*", 'def add(a: int, b: int) -> int:\n    return a + b\n', 
          'def add(a: int, b: int) -> int:\n    return a + b\n', "python"),
    ("*", 'console.log("server started on port 3000");\n',
          'console.log("server started on port 3000");\n', "javascript"),
]


def _ext(lang: str) -> str:
    return {"python": ".py", "javascript": ".js", "go": ".go",
            "java": ".java", "ruby": ".rb"}.get(lang, ".py")


def run_detector_on_case(detector, code: str, lang: str) -> list[dict]:
    """Run one detector on code snippet. Returns matched findings."""
    try:
        tmpdir = tempfile.mkdtemp()
        fpath = Path(tmpdir) / f"snippet{_ext(lang)}"
        fpath.write_text(code, encoding="utf-8")
        ctx = AuditContext(project="bench", path=Path(tmpdir))
        ctx.files = [fpath]
        ctx.get_source_files = lambda *a, **kw: [fpath]
        ctx.file_contents[str(fpath)] = code
        findings = detector.detect(ctx)
        return [f for f in (findings or []) if f is not None]
    except Exception:
        return []


def run_benchmark(rule_filter: str | None = None) -> dict:
    """Run all detectors on all ground truth pairs."""
    all_detectors = {d.rule_id: d for d in get_detectors()}
    counts: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})

    for rule_id, vuln_code, fixed_code, lang in GROUND_TRUTH:
        target_rules = [rule_id] if rule_id != "*" else list(all_detectors.keys())
        if rule_filter and rule_filter not in target_rules:
            continue

        for rule in target_rules:
            if rule_filter and rule != rule_filter:
                continue
            det = all_detectors.get(rule)
            if det is None:
                continue

            # POSITIVE case: vulnerable code — should fire (TP/FN)
            found_vuln = run_detector_on_case(det, vuln_code, lang)
            c = counts[rule]
            c["tp" if found_vuln else "fn"] += 1

            # NEGATIVE case: fixed code — should NOT fire (TN/FP)
            found_fix = run_detector_on_case(det, fixed_code, lang)
            c["fp" if found_fix else "tn"] += 1

    # Compute metrics
    metrics: dict = {"per_rule": {}, "overall": None, "total_pairs": len(GROUND_TRUTH)}
    reliable_scores = []

    for rule, c in sorted(counts.items()):
        tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
        total = tp + fn + fp + tn
        tpr = tp / (tp + fn) if (tp + fn) else None
        fpr = fp / (fp + tn) if (fp + tn) else None
        score = (tpr - fpr) if (tpr is not None and fpr is not None) else None

        metrics["per_rule"][rule] = {**c,
            "tpr": round(tpr, 3) if tpr is not None else None,
            "fpr": round(fpr, 3) if fpr is not None else None,
            "score": round(score, 3) if score is not None else None,
            "total": total}
        if score is not None and total > 0:
            reliable_scores.append(score)

    if reliable_scores:
        metrics["overall"] = round(sum(reliable_scores) / len(reliable_scores), 3)
    return metrics


def print_report(metrics: dict):
    print(f"{'Rule':8} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4}  {'TPR':>6} {'FPR':>6}  {'Score':>7}")
    print("-" * 62)
    for rule, m in sorted(metrics["per_rule"].items()):
        if m["total"] == 0:
            continue
        tpr_s = f"{m['tpr']:.3f}" if m["tpr"] is not None else "  -   "
        fpr_s = f"{m['fpr']:.3f}" if m["fpr"] is not None else "  -   "
        sc_s = f"{m['score']:+.3f}" if m["score"] is not None else "   -   "
        print(f"{rule:8} {m['tp']:>4} {m['fn']:>4} {m['fp']:>4} {m['tn']:>4}  {tpr_s:>6} {fpr_s:>6}  {sc_s:>7}")

    ov = metrics["overall"]
    print(f"\nOverall Score: {ov:+.3f}" if ov is not None else "\nOverall: no data")


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--rule", help="Filter to single rule")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    t0 = time.time()
    metrics = run_benchmark(rule_filter=args.rule)
    if args.json:
        print(json.dumps(metrics, indent=2, default=str))
    else:
        print_report(metrics)
    print(f"Time: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
