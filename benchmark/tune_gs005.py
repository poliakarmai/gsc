#!/usr/bin/env python3
"""GS005 pattern tuning — measure per-pattern TP/FP and disable noisy ones.

Algorithm:
  1. measure_pattern_stats() — TP/FP per pattern_id on benchmark cases
  2. pattern_score = TP_rate - FP_rate (or TP_rate if no FP data)
  3. Sort by score ASC (worst first), test disabling each pattern
  4. TPR guard: skip pattern if TPR drops by >3% after disabling
  5. Disable inline (set `enabled=0` in pattern_status or via ctx)

Usage:
  python3 benchmark/tune_gs005.py          # full tuning
  python3 benchmark/tune_gs005.py --dry-run  # measure only, no disabling
"""
import sys, json, time, tempfile
from pathlib import Path
from collections import defaultdict, Counter

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))

from gsc_detectors import AuditContext
from gsc_detectors.gs005_sql_injection import detect as gs005_detect

MIN_SAMPLE = 2       # minimum trigger count for reliable score
MAX_TPR_DROP = 0.03  # max allowed TPR loss when disabling a pattern
FPR_TARGET = 0.30    # stop when FPR ≤ this

# ── Benchmark cases (vulnerable=True, fixed=False) ─────────────────────────

BENCHMARK = [
    ("query = f\"SELECT * FROM users WHERE id={uid}\"", True),
    ('query = "SELECT * FROM users WHERE id=?"; cursor.execute(query, (uid,))', False),
    ('cursor.execute("SELECT * FROM users WHERE id=" + uid)', True),
    ('cursor.execute("SELECT * FROM users WHERE id=?", (uid,))', False),
    ("db.execute(f\"INSERT INTO logs VALUES ('{msg}')\")", True),
    ('db.execute("INSERT INTO logs VALUES (?)", (msg,))', False),
    ("conn.execute(f\"DELETE FROM sessions WHERE token='{tok}'\"))", True),
    ('conn.execute("DELETE FROM sessions WHERE token=?", (tok,))', False),
    ("session.execute(text(f\"SELECT * FROM users WHERE name='{name}'\"))", True),
    ('session.execute(text("SELECT * FROM users WHERE name=:name"), {"name": name})', False),
    ("User.objects.raw(f\"SELECT * FROM auth_user WHERE username='{u}'\")", True),
    ('User.objects.filter(username=u)', False),
    ('sql = "SELECT * FROM users WHERE id = %s" % user_id', True),
    ('sql = "SELECT * FROM users WHERE id = %s"; cursor.execute(sql, (user_id,))', False),
    ('query = "SELECT * FROM users WHERE id={}".format(uid)', True),
    ('query = "SELECT * FROM users WHERE id=?"; cursor.execute(query, (uid,))', False),
    ('User.objects.raw("SELECT * FROM users WHERE id = " + str(uid))', True),
    ('User.objects.filter(id=uid)', False),
    ('cursor.execute("SELECT * FROM t WHERE x=" + str(x))', True),
    ('cursor.execute("SELECT * FROM t WHERE x=?", (x,))', False),
    # Command injection (GS004 cross-check)
    ('os.system(f"ping {host}")', True),
    ('subprocess.run(["ping", host], check=True)', False),
    ('subprocess.call("nslookup " + domain, shell=True)', True),
    ('subprocess.call(["nslookup", domain])', False),
    # XSS (GS020 cross-check)
    ('return f"<div>{name}</div>"', True),
    ('from markupsafe import escape; return f"<div>{escape(name)}</div>"', False),
    ('response.write("<h1>" + title + "</h1>")', True),
    ('from html import escape; response.write("<h1>" + escape(title) + "</h1>")', False),
    # Clean (should never fire)
    ('def add(a: int, b: int) -> int:\n    return a + b\n', False),
    ('console.log("server started on port 3000");\n', False),
]


def _run(case: tuple[str, bool], disabled: set[str]) -> list[dict]:
    code, is_vuln = case
    tmp = tempfile.mkdtemp()
    fp = Path(tmp) / "test.py"
    fp.write_text(code, encoding="utf-8")
    ctx = AuditContext(project="bench", path=Path(tmp))
    ctx.files = [fp]
    ctx.file_contents[str(fp)] = code
    ctx._disabled_for_test = disabled
    # Override get_disabled_patterns for test
    orig = ctx.get_disabled_patterns
    ctx.get_disabled_patterns = lambda rid: disabled
    findings = gs005_detect(ctx)
    ctx.get_disabled_patterns = orig
    return findings


# ── Block 1-2: Per-pattern stats ──────────────────────────────────────────

def measure_pattern_stats() -> tuple[dict, dict]:
    """Run benchmark, collect TP/FP + case indices per pattern_id."""
    stats: dict[str, dict] = {}
    tp_cases: dict[str, set] = defaultdict(set)
    fp_cases: dict[str, set] = defaultdict(set)

    for case_id, (code, is_vuln) in enumerate(BENCHMARK):
        findings = _run((code, is_vuln), set())
        for f in findings:
            pids = f.get("metadata", {}).get("pattern_ids", [])
            for pid in pids:
                s = stats.setdefault(pid, {"tp": 0, "fp": 0})
                if is_vuln:
                    s["tp"] += 1
                    tp_cases[pid].add(case_id)
                else:
                    s["fp"] += 1
                    fp_cases[pid].add(case_id)

    return stats, {"tp": dict(tp_cases), "fp": dict(fp_cases)}


def compute_scores(stats: dict) -> list[dict]:
    """Compute pattern_score = TP_rate - FP_rate, sorted worst first."""
    total_vuln = sum(1 for _, v in BENCHMARK if v)
    total_safe = sum(1 for _, v in BENCHMARK if not v)

    scored = []
    for pid, s in stats.items():
        tp, fp = s["tp"], s["fp"]
        total_triggers = tp + fp
        tp_rate = tp / total_vuln if total_vuln else 0
        fp_rate = fp / total_safe if total_safe else 0
        score = tp_rate - fp_rate
        scored.append({
            "pid": pid, "tp": tp, "fp": fp, "triggers": total_triggers,
            "tp_rate": round(tp_rate, 3), "fp_rate": round(fp_rate, 3),
            "score": round(score, 3),
            "reliable": total_triggers >= MIN_SAMPLE,
        })
    scored.sort(key=lambda x: x["score"])
    return scored


# ── Block 3: Disable with TPR guard ────────────────────────────────────────

def compute_baseline_tpr() -> float:
    """TPR on vuln cases with no patterns disabled."""
    tp = fn = 0
    for code, is_vuln in BENCHMARK:
        if not is_vuln:
            continue
        findings = _run((code, is_vuln), set())
        if findings: tp += 1
        else: fn += 1
    return tp / (tp + fn) if (tp + fn) else 0


def compute_fpr(disabled: set[str]) -> float:
    """FPR on safe cases with given patterns disabled."""
    fp = tn = 0
    for code, is_vuln in BENCHMARK:
        if is_vuln:
            continue
        findings = _run((code, is_vuln), disabled)
        if findings: fp += 1
        else: tn += 1
    return fp / (fp + tn) if (fp + tn) else 0


def compute_tpr(disabled: set[str]) -> float:
    """TPR on vuln cases with given patterns disabled."""
    tp = fn = 0
    for code, is_vuln in BENCHMARK:
        if not is_vuln:
            continue
        findings = _run((code, is_vuln), disabled)
        if findings: tp += 1
        else: fn += 1
    return tp / (tp + fn) if (tp + fn) else 0


def test_disable(pid: str, baseline_tpr: float) -> tuple[float, float, bool]:
    """Test disabling one pattern: returns (new_tpr, new_fpr, safe_to_disable)."""
    new_tpr = compute_tpr({pid})
    tpr_drop = baseline_tpr - new_tpr
    return new_tpr, compute_fpr({pid}), tpr_drop <= MAX_TPR_DROP


# ── Block 4: Overlap analysis ──────────────────────────────────────────────

def overlap_coefficient(set1: set, set2: set) -> float:
    """Jaccard-like overlap: |intersection| / min(|set1|, |set2|)."""
    if not set1 or not set2:
        return 0.0
    return len(set1 & set2) / min(len(set1), len(set2))


def find_correlated(pid: str, case_index: dict, threshold: float = 0.7) -> list[str]:
    """Find patterns that fire on same FP cases (overlap ≥70%)."""
    my_fp = case_index["fp"].get(pid, set())
    if not my_fp:
        return []
    correlated = []
    for other, their_fp in case_index["fp"].items():
        if other == pid:
            continue
        ov = overlap_coefficient(my_fp, their_fp)
        if ov >= threshold:
            correlated.append(other)
    return correlated


# ── Block 5: Pipeline ─────────────────────────────────────────────────────

def tune_gs005(dry_run: bool = True):
    """Full tuning pipeline."""
    t0 = time.time()

    # 1. Measure per-pattern stats
    print("=" * 65)
    print("Step 1: Measure per-pattern TP/FP")
    stats, case_index = measure_pattern_stats()
    scored = compute_scores(stats)
    print(f"  Patterns with data: {len(scored)}")

    # 2. Baseline
    baseline_tpr = compute_baseline_tpr()
    baseline_fpr = compute_fpr(set())
    print(f"\nStep 2: Baseline TPR={baseline_tpr:.3f} FPR={baseline_fpr:.3f}")

    # 3. Print scored patterns
    print(f"\n{'Pattern':24s} {'TP':>4} {'FP':>4} {'tpr':>6} {'fpr':>6} {'Score':>7} {'Rel'}")
    print("-" * 65)
    for s in scored:
        rel = " ✓" if s["reliable"] else " ⚠"
        print(f"{s['pid']:24s} {s['tp']:>4} {s['fp']:>4} "
              f"{s['tp_rate']:>6.3f} {s['fp_rate']:>6.3f} {s['score']:>+7.3f}{rel}")

    # 4. Test disabling — worst first
    print(f"\nStep 4: Test disabling (TPR guard: drop ≤ {MAX_TPR_DROP:.0%})")
    disabled = set()
    tried = []

    for s in scored:
        if not s["reliable"]:
            continue
        pid = s["pid"]
        new_tpr, new_fpr, safe = test_disable(pid, baseline_tpr)
        tried.append((pid, new_tpr, new_fpr, safe))
        if safe:
            disabled.add(pid)
            status = "✅ DISABLED"
        else:
            status = f"⛔ TPR DROP {baseline_tpr - new_tpr:.3f}"
        print(f"  {pid:24s} TPR={new_tpr:.3f} FPR={new_fpr:.3f} {status}")

        if new_fpr <= FPR_TARGET:
            break

    # 5. Overlap analysis
    print(f"\nStep 5: Correlated patterns (overlap ≥ 70% on FP cases)")
    has_overlap = False
    for s in scored:
        if s["fp"] <= 1:
            continue
        correlated = find_correlated(s["pid"], case_index)
        if correlated:
            has_overlap = True
            print(f"  {s['pid']} triggers with: {', '.join(correlated)}")
    if not has_overlap:
        print("  No significant overlaps")

    # 6. Apply
    final_tpr = compute_tpr(disabled)
    final_fpr = compute_fpr(disabled)
    print(f"\n{'=' * 65}")
    print(f"Result: TPR {baseline_tpr:.3f}→{final_tpr:.3f} "
          f"({(final_tpr - baseline_tpr)*100:+.1f}%)  "
          f"FPR {baseline_fpr:.3f}→{final_fpr:.3f} "
          f"({(final_fpr - baseline_fpr)*100:+.1f}%)")
    print(f"Disabled: {len(disabled)} patterns")
    for pid in sorted(disabled):
        s = next(x for x in scored if x["pid"] == pid)
        print(f"  {pid}: tp={s['tp']} fp={s['fp']} score={s['score']}")
    print(f"\nTime: {time.time() - t0:.1f}s")

    if dry_run:
        print("\n[Dry run — no patterns actually disabled. Remove --dry-run to apply.]")
        return disabled, scored

    # Apply to pattern_status table
    try:
        import sqlite3
        db = sqlite3.connect(str(Path.home() / ".hermes/state/gsc_audit.db"))
        for pid in disabled:
            s = next(x for x in scored if x["pid"] == pid)
            db.execute(
                "INSERT OR REPLACE INTO pattern_status "
                "(pattern_id, rule_id, enabled, measured_precision, "
                " true_positives, false_positives, sample_size, "
                " disabled_reason, disabled_at) "
                "VALUES (?, ?, 0, ?, ?, ?, ?, ?, datetime('now'))",
                (pid, "GS005", 1 - s["fp_rate"], s["tp"], s["fp"],
                 s["triggers"], f"Auto-tuned: FPR={final_fpr:.3f}"))
        db.commit()
        db.close()
        print("✅ Applied to pattern_status table")
    except Exception as e:
        print(f"❌ Failed to apply: {e}")

    return disabled, scored


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry_run = "--apply" not in sys.argv
    disabled, scored = tune_gs005(dry_run=dry_run)
