#!/usr/bin/env python3
"""GSC Reconciliation — validate docs match reality.

Single source of truth: gsc_meta.get_meta(). Every consumer (README, AGENTS.md,
server, CLI) must read numbers from there, never hardcode a count.
"""
from __future__ import annotations

import sys
from pathlib import Path

GSC = Path(__file__).parent.parent
sys.path.insert(0, str(GSC))

from gsc_meta import get_meta


def main() -> int:
    meta = get_meta()
    ag = (GSC / "AGENTS.md").read_text(errors="ignore")
    readme = (GSC / "README.md").read_text(errors="ignore")

    total = meta["detectors_total"]
    reg = meta["detectors_registry"]
    standalone = meta["detectors_standalone"]
    schema = meta["schema"]
    version = meta["version"]

    issues: list[str] = []

    # Version must appear in both AGENTS.md and README.md
    for name, text in (("AGENTS.md", ag), ("README.md", readme)):
        if f"v{version}" not in text:
            issues.append(f"{name}: version v{version} not found")

    # Detector count (total = registry + standalone)
    for name, text in (("AGENTS.md", ag), ("README.md", readme)):
        if f"{total} детектор" not in text and f"{total} detectors" not in text.lower():
            issues.append(f"{name}: detector total {total} not found")

    # Schema version
    if f"Schema:** {schema}" not in ag and f"schema {schema}" not in ag.lower():
        issues.append(f"AGENTS.md: schema {schema} not found")

    print("=" * 60)
    print("GSC RECONCILIATION")
    print(f"  SSOT: v{version}, {total} detectors ({reg} registry + "
          f"{standalone} standalone), schema v{schema}, {meta['modules']} modules")

    if issues:
        print(f"\n  DISCREPANCIES: {len(issues)}")
        for i in issues:
            print(f"    - {i}")
        return 1

    print("\n  ALL MATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
