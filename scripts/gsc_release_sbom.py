#!/usr/bin/env python3
"""GSC release SBOM — CycloneDX 1.5 из requirements.txt (due-diligence шаг 5).

Release-процесс должен прикреплять `dist/sbom.cdx.json` к GitHub Release
(или image attestation), а не полагаться на mutable tag без SBOM.

Использование:
    python3 scripts/gsc_release_sbom.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _version(root: Path) -> str:
    vf = root / "VERSION"
    if vf.exists():
        return vf.read_text().strip()
    try:
        import tomllib
        return tomllib.loads((root / "pyproject.toml").read_text()).get("project", {}).get("version", "unknown")
    except Exception:
        return "unknown"


def parse_requirements(path: Path) -> list[dict]:
    pkgs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name, _, ver = line.partition("==")
        pkgs.append({"name": name.strip().lower(), "version": (ver.strip() or None)})
    return pkgs


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    req = root / "requirements.txt"
    out = root / "dist" / "sbom.cdx.json"
    if not req.exists():
        print("requirements.txt not found", file=sys.stderr)
        return 1

    components, seen = [], set()
    for p in parse_requirements(req):
        purl = f"pkg:pypi/{p['name']}" + (f"@{p['version']}" if p["version"] else "")
        if purl in seen:
            continue
        seen.add(purl)
        components.append({
            "type": "library",
            "bom-ref": hashlib.sha256(purl.encode()).hexdigest()[:16],
            "name": p["name"],
            "version": p.get("version") or "",
            "purl": purl,
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": "gsc", "version": _version(root)},
        },
        "components": components,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2) + "\n")
    print(f"✅ SBOM → {out} ({len(components)} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
