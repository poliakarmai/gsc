"""Compliance reporting — SOC2, PCI-DSS, ISO 27001 (v0.38)."""
from typing import Dict, List

FRAMEWORKS = {
    "SOC2": {"CC6.1":["GS019","GS029"],"CC6.6":["GS001","GS005"],"CC7.1":["GS030","GS031"],"CC8.1":["GS028"]},
    "PCI-DSS": {"6.5.1":["GS001","GS005"],"6.5.7":["GS017"],"6.5.5":["GS019","GS029"],"11.2":["GS030"]},
    "ISO27001": {"A.12.6.1":["GS030","GS031"],"A.14.2.1":["GS028"],"A.10.1.1":["GS019","GS029"]},
}

def map_finding(finding_rule: str) -> Dict[str,List[str]]:
    base = finding_rule.split("-")[0]
    r = {}
    for fw, ctrls in FRAMEWORKS.items():
        m = [c for c, rules in ctrls.items() if base in rules]
        if m: r[fw] = m
    return r

def generate_report(findings: List[Dict], framework: str) -> Dict:
    if framework not in FRAMEWORKS: raise ValueError(f"Unknown: {framework}")
    ctrls = FRAMEWORKS[framework]
    report = {"framework": framework, "total": len(findings), "controls": {}}
    for c, rules in ctrls.items():
        matched = [f for f in findings if f.get("rule_id","").split("-")[0] in rules]
        report["controls"][c] = {"rules": rules, "findings": len(matched),
            "critical": sum(1 for f in matched if f.get("severity")=="CRITICAL"),
            "high": sum(1 for f in matched if f.get("severity")=="HIGH")}
    return report
