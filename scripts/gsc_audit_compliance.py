#!/usr/bin/env python3
"""scripts/gsc_audit_compliance.py — verify COMPLIANCE_MAP against detector registry."""
import sys
sys.path.insert(0, ".")
from gsc_compliance import COMPLIANCE_MAP
try:
    from gsc_detectors import DETECTORS
    real_rules = {d.rule_id.split("-")[0] for d in DETECTORS if hasattr(d, 'rule_id')}
except ImportError:
    real_rules = set()
    print("⚠ Could not import DETECTORS — skipping detector audit")

print(f"Detectors in registry: {len(real_rules) if real_rules else '?'}")
if real_rules:
    print(f"  {sorted(real_rules)}")

unmapped = [r for r in sorted(real_rules) if r not in COMPLIANCE_MAP]
unknown = [r for r in COMPLIANCE_MAP if r.split("-")[0] not in real_rules]

print(f"\nDetectors WITHOUT compliance mapping: {unmapped or 'none'}")
print(f"COMPLIANCE_MAP references unknown detectors: {unknown or 'none'}")

total = len(COMPLIANCE_MAP)
covered = total - len(unknown)
print(f"\nCoverage: {covered}/{total} rules ({100*covered//total}% mapped)")
