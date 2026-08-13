"""Phase 0 — замер разрыва PoC-верификации (методика §2.5 экспертизы #1).

Считает: сколько findings получили PoC и сколько PoC «прошли» по SUCCESS_MARKERS
в песочнице. Разрыв между «прошёл по маркеру» и «реально эксплуатирует» — отдельная
ручная проверка (этот скрипт даёт только полуавтоматическую часть).

Использование:
  python3 scripts/gsc_poc_gap_measure.py --repo benchmark/real_world/httpie --json
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_external import run_external_scan
from gsc_poc_generator import attach_pocs
from gsc_pof_sandbox import PoFSandbox


def _source_map(repo: Path, findings: list[dict]) -> dict:
    m = {}
    for f in findings:
        fp = f.get("file_path", "")
        if not fp:
            continue
        p = repo / fp
        if p.exists():
            try:
                m[fp] = p.read_text(errors="ignore")
            except OSError:
                pass
    return m


def measure(repo: str, poc_budget: int = 5, max_run: int = 0) -> dict:
    t0 = time.time()
    result = run_external_scan(repo, profile_name="audit", scan_mode="standard")
    findings = result.findings
    total = len(findings)

    source_map = _source_map(Path(repo), findings)
    attach_pocs(findings, source_map, budget=poc_budget)

    with_poc = [f for f in findings if f.get("metadata", {}).get("poc")]
    sandbox = PoFSandbox()
    passed = 0
    run = 0
    for f in with_poc:
        if max_run and run >= max_run:
            break
        poc = f["metadata"]["poc"]
        src = source_map.get(f.get("file_path", ""), "")
        fmt = f.get("metadata", {}).get("poc_format", "python")
        res = sandbox._execute(poc, src, fmt=fmt)
        run += 1
        if res.success:
            passed += 1

    return {
        "repo": repo,
        "findings_total": total,
        "with_poc": len(with_poc),
        "poc_executed": run,
        "poc_passed_marker": passed,
        "pass_rate": round(passed / run, 3) if run else 0.0,
        "elapsed_s": round(time.time() - t0, 1),
    }


def main() -> int:
    p = argparse.ArgumentParser(description="GSC PoC gap measurement (Phase 0)")
    p.add_argument("--repo", required=True)
    p.add_argument("--poc-budget", type=int, default=5)
    p.add_argument("--max-run", type=int, default=0, help="0 = run all PoCs")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    m = measure(args.repo, args.poc_budget, args.max_run)
    if args.json:
        print(json.dumps(m, indent=2, ensure_ascii=False))
    else:
        for k, v in m.items():
            print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
