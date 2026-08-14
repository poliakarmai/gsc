#!/usr/bin/env python3
"""GSC release manifest (roadmap 5.4) — машиночитаемый отчёт о release.

Собирает версию, commit SHA, SHA256 wheel/SBOM, digest sandbox-образа,
количество детекторов и schema version. Пишет ``dist/release-manifest.json``.
Прикрепляется к GitHub Release / image attestation как SBOM-сосед.

Запуск:  python3 scripts/gsc_release_manifest.py
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str | None:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def _project_version() -> str | None:
    try:
        import tomllib
        return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        return None


def _detectors() -> dict:
    """SSOT-цифры через gsc_meta (не хардкод) — см. AGENTS.md."""
    sys.path.insert(0, str(ROOT))
    try:
        import gsc_meta
        meta = gsc_meta.get_meta()
        return {
            "registry": meta.get("detectors_registry"),
            "standalone": meta.get("detectors_standalone"),
            "total": meta.get("detectors_total"),
        }
    except Exception as e:  # noqa: BLE001 — manifest не должен падать на мете
        return {"error": str(e)}


def _schema_version() -> int | None:
    sys.path.insert(0, str(ROOT))
    try:
        from gsc_db import TARGET_VERSION
        return TARGET_VERSION
    except Exception:
        return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest: dict = {
        "manifest_version": 1,
        "name": "gsc-security",
        "version": _project_version(),
        "commit": _git("rev-parse", "HEAD"),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "detectors": _detectors(),
        "schema_version": _schema_version(),
        "artifacts": {},
    }

    wheels = sorted(ROOT.glob("dist/*.whl"))
    if wheels:
        w = wheels[-1]
        manifest["artifacts"]["wheel"] = {"name": w.name, "sha256": _sha256(w)}

    sbom = ROOT / "dist" / "sbom.cdx.json"
    if sbom.exists():
        manifest["artifacts"]["sbom"] = {"name": sbom.name, "sha256": _sha256(sbom)}

    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}",
             "gsc-sandbox:latest"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            manifest["artifacts"]["sandbox_image"] = r.stdout.strip()
    except Exception:
        pass

    out = ROOT / "dist" / "release-manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"✅ release-manifest.json → {out}")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
