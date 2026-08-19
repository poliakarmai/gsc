# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC Business-Risk Scoring v1.0.

Приоритизация находок по БИЗНЕС-контексту, а не только по CVSS/severity.

risk = sev_weight × business_weight × reachability × (1 + 0.2×chain_len) × epss_factor

- business_weight: 3.0 если путь попадает в критичные зоны (payments/, auth/, ...)
- reachability: 1.0 (или 0.5 для dev-dependency SCA) — из gsc_epss
- chain_len: длина exploit-цепочки, в которую входит находка (из ChainComposer)
- epss_factor: 0.5 + epss, только если находка SCA с EPSS (иначе 1.0)

Pure-модуль без БД/LLM — переиспользует gsc_epss.SEVERITY_WEIGHT и
estimate_reachability. Заимствовано из идеи "business-risk weighted PR".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from gsc_core.gsc_epss import SEVERITY_WEIGHT, estimate_reachability

DEFAULT_CRITICAL_PATHS = (
    "payments/", "payment/", "billing/", "checkout/",
    "auth/", "login/", "session/", "token/",
    "admin/", "secrets/", "credential/", "key/",
)

BUSINESS_WEIGHT_CRITICAL = 3.0
BUSINESS_WEIGHT_DEFAULT = 1.0
CHAIN_FACTOR = 0.2          # +20% риска на каждое звено цепочки
EPSS_FLOOR = 0.5            # epss_factor = 0.5 + epss  →  [0.5, 1.5]


def business_weight(file_path: str,
                    critical_paths: Optional[tuple] = None) -> float:
    """3.0 для критичного пути, 1.0 иначе. Пути сравниваются по подстроке."""
    paths = critical_paths or DEFAULT_CRITICAL_PATHS
    fp = (file_path or "").replace("\\", "/").lower()
    return BUSINESS_WEIGHT_CRITICAL if any(p.lower() in fp for p in paths) \
        else BUSINESS_WEIGHT_DEFAULT


def _chain_len(finding: dict, chains: Optional[List]) -> int:
    """Длина цепочки, в которую входит finding (0 если не в цепочке)."""
    if not chains:
        return 0
    fk = finding.get("finding_key", "")
    for ch in chains:
        keys = ch.get("finding_keys", []) if isinstance(ch, dict) \
            else getattr(ch, "finding_keys", [])
        if fk in (keys or []):
            return len(keys)
    return 0


def compute_business_risk(finding: dict,
                          chains: Optional[List] = None,
                          critical_paths: Optional[tuple] = None) -> dict:
    """Вычислить business-risk для одной находки. Возвращает dict со score/level/formula."""
    sev = str(finding.get("severity", finding.get("category", "MEDIUM"))).upper()
    sev_weight = SEVERITY_WEIGHT.get(sev, 0.5)

    fp = finding.get("file", finding.get("file_path", ""))
    bw = business_weight(fp, critical_paths)
    reach = estimate_reachability(finding)
    cl = _chain_len(finding, chains)

    score = sev_weight * bw * reach * (1.0 + CHAIN_FACTOR * cl)

    # EPSS-фактор — только если находка уже обогащена EPSS (SCA/CVE)
    epss = None
    meta = finding.get("metadata", {})
    if isinstance(meta, dict):
        epss = meta.get("epss", {}).get("score") if isinstance(meta.get("epss"), dict) else None
    epss_factor = 1.0
    if epss is not None:
        try:
            epss_factor = EPSS_FLOOR + max(0.0, min(1.0, float(epss)))
        except (TypeError, ValueError):
            epss_factor = 1.0
    score *= epss_factor

    level = ("critical" if score >= 2.0 else
             "high" if score >= 0.8 else
             "medium" if score >= 0.4 else "low")

    formula = (
        f"sev({sev_weight}) × biz({bw}) × reach({reach}) × "
        f"chain(1+{CHAIN_FACTOR}×{cl}) × epss({epss_factor:.2f})"
    )
    return {
        "score": round(score, 3),
        "level": level,
        "business_weight": bw,
        "chain_len": cl,
        "epss_factor": round(epss_factor, 3),
        "critical_path": bw > BUSINESS_WEIGHT_DEFAULT,
        "formula": formula,
    }


def prioritize(findings: List[dict],
               chains: Optional[List] = None,
               critical_paths: Optional[tuple] = None) -> List[dict]:
    """Вернуть копию findings, отсортированную по business-risk (desc),
    с аннотацией metadata.business_risk у каждой."""
    scored = []
    for f in findings:
        r = compute_business_risk(f, chains, critical_paths)
        f2 = dict(f)
        meta = dict(f2.get("metadata") or {})
        meta["business_risk"] = r
        f2["metadata"] = meta
        scored.append((r["score"], f2))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored]


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="GSC business-risk prioritisation")
    ap.add_argument("scan_json", help="scan.json (findings)")
    ap.add_argument("--chains-json", help="chains.json (ChainComposer output)")
    ap.add_argument("--critical-paths", help="comma-separated extra critical paths")
    ap.add_argument("--output", "-o", help="save re-prioritised report")
    ap.add_argument("--top", type=int, default=10, help="show top N")
    args = ap.parse_args()

    report = json.loads(Path(args.scan_json).read_text())
    findings = report.get("findings", [])

    chains = None
    if args.chains_json:
        cd = json.loads(Path(args.chains_json).read_text())
        chains = cd.get("chains", cd if isinstance(cd, list) else [])

    extra = tuple(p.strip() for p in (args.critical_paths or "").split(",") if p.strip())
    critical_paths = DEFAULT_CRITICAL_PATHS + extra if extra else None

    prio = prioritize(findings, chains, critical_paths)
    print(f"Re-prioritised {len(prio)} findings by business risk")
    for f in prio[:args.top]:
        br = f["metadata"]["business_risk"]
        print(f"  {br['score']:5.2f} [{br['level']:8}] "
              f"{f.get('rule_id','?')} {f.get('file_path', f.get('file','?'))} "
              f"— {f.get('title','')[:60]}"
              + ("  ⚠️ CRITICAL PATH" if br["critical_path"] else ""))

    if args.output:
        report["findings"] = prio
        Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"→ {args.output}")


if __name__ == "__main__":
    main()
