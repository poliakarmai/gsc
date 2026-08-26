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
    modules = meta["modules"]

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

    # Module count (was a blind spot — reconcile only checked version/detectors/schema)
    for name, text in (("AGENTS.md", ag), ("README.md", readme)):
        if (f"{modules} модул" not in text and f"{modules} modules" not in text.lower()
                and f"Modules:** {modules}" not in text):
            issues.append(f"{name}: modules {modules} not found")

    # Test-file count (informational — exact test count is pytest --collect-only)
    test_files = len(list((GSC / "tests").glob("test_*.py")))
    print(f"  test files (tests/test_*.py): {test_files} — exact count via `pytest --collect-only -q | tail -1`")

    # DD-03: marketing one-pager (HTML) must match SSOT too.
    onepager = GSC / "marketing" / "gsc-onepager-yandex.html"
    if onepager.exists():
        op = onepager.read_text(errors="ignore")
        if f"{total} детектор" not in op and f"{total} detectors" not in op.lower():
            issues.append(f"marketing/gsc-onepager-yandex.html: detectors {total} not found")
        if f"{modules} модул" not in op and f"{modules} modules" not in op.lower():
            issues.append(f"marketing/gsc-onepager-yandex.html: modules {modules} not found")
        if f"schema {schema}" not in op and f"schema v{schema}" not in op.lower():
            issues.append(f"marketing/gsc-onepager-yandex.html: schema {schema} not found")
        if f"v{version}" not in op:
            issues.append(f"marketing/gsc-onepager-yandex.html: version v{version} not found")

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
