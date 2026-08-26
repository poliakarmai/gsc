#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC DAST Validator v1.0 — Wave 3.

Verifies Proof-of-Fix on staging via nuclei.
Adds DAST layer: sandbox → nuclei staging → full verification.

Cycle: SAST → PoC → fix → sandbox → re-PoC → DAST staging → verified.
"""

from __future__ import annotations

import subprocess, sys, tempfile
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))


class DastValidator:
    """Validates security fixes on staging via nuclei DAST."""

    def __init__(self, staging_url: str, timeout_sec: int = 300,
                 severity_filter: List[str] = None):
        self.staging_url = staging_url
        self.timeout_sec = timeout_sec
        self.severity_filter = severity_filter or ["critical", "high"]

    def validate_fix(self, finding: dict, poc_code: str,
                     evidence: dict = None) -> dict:
        """Verify fix on staging via nuclei.

        Returns: {dast_verified, dast_output, dast_exit}
          dast_verified=True  → staging is safe (fix works)
          dast_verified=False → staging still vulnerable (fix incomplete)
          dast_verified=None  → test skipped/unavailable
        """
        # SSRF guard: the staging URL must not resolve to the machine's own network
        # position (metadata endpoint, loopback, private space) before nuclei is pointed at it.
        from gsc_core.gsc_ssrf_guard import guard_url
        try:
            guard_url(self.staging_url)
        except PermissionError as e:
            return {"dast_verified": None, "dast_output": f"SSRF guard: {e}", "dast_exit": None}

        severity = finding.get("severity", finding.get("category", "medium")).lower()
        if severity not in self.severity_filter:
            return {"dast_verified": None, "dast_output": "skipped (severity)",
                    "dast_exit": None}

        # Export PoC to nuclei YAML
        from gsc_nuclei_export import export_finding_to_nuclei
        template = export_finding_to_nuclei(finding, poc_code)
        if not template:
            return {"dast_verified": None, "dast_output": "PoC not exportable to nuclei",
                    "dast_exit": None}

        with tempfile.TemporaryDirectory(prefix="gsc_dast_") as tmpdir:
            template_path = Path(tmpdir) / f"{template.id}.yaml"
            template_path.write_text(template.to_yaml(), encoding="utf-8")

            cmd = ["nuclei", "-t", str(template_path), "-u", self.staging_url, "-silent"]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.timeout_sec)
            except subprocess.TimeoutExpired:
                return {"dast_verified": None,
                        "dast_output": f"nuclei timed out ({self.timeout_sec}s)",
                        "dast_exit": None}
            except FileNotFoundError:
                return {"dast_verified": None, "dast_output": "nuclei not found in PATH",
                        "dast_exit": None}

            # nuclei: exit 0 = findings found, exit 1 = no findings, exit 2+ = error
            # For fix verification: exit 1 (no findings) = fix works ✅
            if proc.returncode == 1:
                return {"dast_verified": True,
                        "dast_output": "nuclei found no vulnerabilities on staging ✅",
                        "dast_exit": 1}
            elif proc.returncode == 0:
                return {"dast_verified": False,
                        "dast_output": f"nuclei STILL finds vulnerability: {proc.stdout[:200]}",
                        "dast_exit": 0}
            else:
                return {"dast_verified": None,
                        "dast_output": f"nuclei error (exit {proc.returncode}): {proc.stderr[:200]}",
                        "dast_exit": proc.returncode}


def validate_fix_on_staging(finding: dict, poc_code: str,
                            evidence: dict, staging_url: str,
                            timeout_sec: int = 300) -> dict:
    """Wrapper for Proof-of-Fix integration."""
    validator = DastValidator(staging_url, timeout_sec)
    return validator.validate_fix(finding, poc_code, evidence)
