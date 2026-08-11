#!/usr/bin/env python3
"""OWASP Benchmark — fast benchmark (direct detector loading, no registry overhead).
Usage: python3 benchmark/run_owasp_fast.py
"""
import sys, json, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.adapter import parse_owasp_benchmark
from benchmark.runner import scan_test_case, is_detected
from benchmark.cwe_map import build_cwe_to_rules, coverage_report

BENCHMARK_ROOT = "/tmp/OWASP-Benchmark"
EXPECTED_CSV = f"{BENCHMARK_ROOT}/expectedresults-1.2.csv"

# CWE → (detector module, rule_id)
CWE_DETECTORS = {
    "CWE-78": ("gsc_detectors.gs004_dangerous_subprocess", "GS004"),
    "CWE-79": ("gsc_detectors.gs020_xss_injection", "GS020"),
    "CWE-89": ("gsc_detectors.gs005_sql_injection", "GS005"),
}


def main():
    limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--limit" else 0

    t0 = time.time()
    print("Loading test cases...")
    test_cases = parse_owasp_benchmark(BENCHMARK_ROOT, EXPECTED_CSV)
    if limit:
        test_cases = test_cases[:limit]
    print(f"  {len(test_cases)} test cases")
    vuln = sum(1 for t in test_cases if t.is_vulnerable)
    safe = sum(1 for t in test_cases if not t.is_vulnerable)
    print(f"  {vuln} vulnerable, {safe} safe")

    # Load detectors lazily by CWE
    cwe_to_det = {}
    for cwe, (mod, rid) in CWE_DETECTORS.items():
        m = __import__(mod, fromlist=["detect"])
        class Det:
            rule_id = rid
            requires_llm = False
            def detect(self, ctx): return m.detect(ctx)
        cwe_to_det[cwe] = Det()

    # Run per CWE — one detector at a time
    scores = {}
    for cwe, det in cwe_to_det.items():
        cases = [tc for tc in test_cases if tc.cwe == cwe]
        if not cases:
            continue
        tp = fp = fn = tn = 0
        for tc in cases:
            findings = scan_test_case([det], tc)
            detected = is_detected(findings, [det.rule_id])
            if tc.is_vulnerable:
                if detected: tp += 1
                else: fn += 1
            else:
                if detected: fp += 1
                else: tn += 1
        tpr = tp / (tp + fn) if (tp + fn) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        scores[cwe] = {
            "cwe": cwe, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "tpr": round(tpr, 3), "fpr": round(fpr, 3),
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0,
            "owasp_score": round(tpr - fpr, 3),
            "total": tp + fp + fn + tn,
        }
        print(f"  {cwe}: TPR={tpr:.3f} FPR={fpr:.3f} "
              f"(TP={tp} FP={fp} FN={fn} TN={tn})")

    owasp_avg = round(sum(s["owasp_score"] for s in scores.values()) / len(scores), 3) if scores else 0
    print(f"\nOWASP Score: {owasp_avg}")

    cov = coverage_report(build_cwe_to_rules())
    print(f"Coverage: {cov['coverage_pct']}%")

    elapsed = time.time() - t0
    print(f"Total: {elapsed:.1f}s")

    out = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "test_cases": len(test_cases),
        "cwe_scores": scores,
        "owasp_score": owasp_avg,
        "coverage": cov,
        "elapsed_s": round(elapsed, 1),
    }
    outpath = Path(__file__).resolve().parent / "owasp_results.json"
    json.dump(out, open(outpath, "w"), indent=2)
    print(f"Saved: {outpath}")


if __name__ == "__main__":
    main()
