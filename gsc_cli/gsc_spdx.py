#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC SPDX 2.3 + SBOM Signing v1.0 (v0.35).

SPDX generation from SCA packages, CycloneDX→SPDX conversion,
HMAC-SHA256 SBOM signing with tamper detection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

DOWNLOAD_LOC = {
    "PyPI": "https://pypi.org/project/{name}", "npm": "https://www.npmjs.com/package/{name}",
    "Go": "https://{name}", "crates.io": "https://crates.io/crates/{name}",
    "Maven": "https://search.maven.org/search?q={name}", "RubyGems": "https://rubygems.org/gems/{name}",
}


# ── SPDX Generator ─────────────────────────────────────────
def _spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^a-zA-Z0-9.\-]", "-", name)

def _dl(ecosystem: str, name: str) -> str:
    t = DOWNLOAD_LOC.get(ecosystem, "NOASSERTION")
    return t.format(name=name) if t != "NOASSERTION" else t

def _uid() -> str: return str(uuid.uuid4())

def generate_spdx(packages: List, tool_version: str = "0.35", doc_name: str = "gsc-sbom",
                  licenses: Optional[Dict] = None) -> dict:
    from gsc_sbom import make_purl
    pkgs, rels, seen = [], [], set()
    for p in packages:
        sid = _spdx_id(f"{p.name}-{p.version or 'none'}")
        if sid in seen: continue
        seen.add(sid)
        pkg = {"SPDXID": sid, "name": p.name, "versionInfo": p.version or "",
               "downloadLocation": _dl(p.ecosystem, p.name), "filesAnalyzed": False,
               "externalRefs": [{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
                                  "referenceLocator": make_purl(p.ecosystem, p.name, p.version)}]}
        if licenses:
            lic = licenses.get(f"{p.ecosystem}:{p.name.lower()}")
            if lic:
                pkg["licenseConcluded"] = lic
                pkg["licenseDeclared"] = lic
        pkgs.append(pkg)
        rels.append({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":sid})
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
            "name": doc_name, "documentNamespace": f"https://spdx.org/spdxdocs/gsc-{_uid()}",
            "creationInfo": {"created": datetime.now(timezone.utc).isoformat(),
                             "creators": [f"Tool: gsc-sbom-{tool_version}"]},
            "packages": pkgs, "relationships": rels}


# ── CDX → SPDX Conversion ──────────────────────────────────
def _eco(purl: str) -> str:
    if not purl.startswith("pkg:"): return ""
    return {"pypi":"PyPI","npm":"npm","golang":"Go","cargo":"crates.io",
            "maven":"Maven","gem":"RubyGems"}.get(purl[4:].split("/")[0].lower(), "")

def cdx_to_spdx(cdx: dict, doc_name: str = "gsc-sbom") -> dict:
    pkgs, rels, seen = [], [], set()
    for c in cdx.get("components", []):
        name, ver = c.get("name","unknown"), c.get("version","")
        sid = _spdx_id(f"{name}-{ver or 'none'}")
        if sid in seen: continue
        seen.add(sid)
        purl = c.get("purl","")
        ext = [{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":purl}] if purl else []
        pkgs.append({"SPDXID":sid,"name":name,"versionInfo":ver,
                     "downloadLocation":_dl(_eco(purl),name),"filesAnalyzed":False,"externalRefs":ext})
        rels.append({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":sid})
    tools = cdx.get("metadata",{}).get("tools",[])
    creator = tools[0].get("name","gsc-sbom") if tools else "gsc-sbom"
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
            "name":doc_name,"documentNamespace":f"https://spdx.org/spdxdocs/gsc-{_uid()}",
            "creationInfo":{"created":datetime.now(timezone.utc).isoformat(),"creators":[f"Tool: {creator}"]},
            "packages":pkgs,"relationships":rels}


# ── Signing ────────────────────────────────────────────────
def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()

def sign_sbom(sbom: dict, key: bytes) -> dict:
    content = canonical_json(sbom)
    return {"algorithm":"HMAC-SHA256","digest":hmac.new(key,content,hashlib.sha256).hexdigest(),
            "key_id": hashlib.sha256(key).hexdigest()[:16],
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "package_count": len(sbom.get("packages", sbom.get("components",[])))}

def verify_sbom(sbom: dict, signature: dict, key: bytes) -> bool:
    content = canonical_json(sbom)
    return hmac.compare_digest(hmac.new(key,content,hashlib.sha256).hexdigest(),
                                signature.get("digest",""))

def load_signing_key() -> Optional[bytes]:
    env = os.environ.get("GSC_SBOM_KEY")
    if env: return env.encode()
    kf = Path.home() / ".gsc" / "sbom.key"
    if kf.exists(): return kf.read_bytes()
    return None
