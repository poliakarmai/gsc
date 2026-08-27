# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS009 — Supply Chain Scanner (Bumblebee integration).

Scans developer endpoint for:
- Package manager artifacts (npm, PyPI, Go, Ruby, Composer, Homebrew)
- Editor extensions (VS Code, Cursor, Windsurf)
- MCP configurations
- Browser extensions
- Agent skills

Delegates to bumblebee CLI (Perplexity, Apache 2.0).
"""
import json
import os
import subprocess
from typing import List, Optional

from . import Finding

RULE_ID = "GS009"
ECHELON = 2  # Security echelon — supply chain is a real threat vector
SEVERITY = "HIGH"
CATEGORY = "supply-chain"
description = (
    "Supply chain scanner: detects packages, editor extensions, MCP configs, "
    "and developer-tool metadata across package ecosystems (npm, PyPI, Go, "
    "Ruby, Composer, Homebrew, MCP, editor-extension, browser-extension, agent-skill). "
    "Powered by Perplexity Bumblebee."
)

BUMBLEBEE_BIN = os.path.expanduser("~/go/bin/bumblebee")


def _find_bumblebee() -> Optional[str]:
    """Locate bumblebee binary."""
    if os.path.isfile(BUMBLEBEE_BIN) and os.access(BUMBLEBEE_BIN, os.X_OK):
        return BUMBLEBEE_BIN
    # Try PATH
    for path in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(path, "bumblebee")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def detect(ctx) -> List[Finding]:
    """Scan with Bumblebee and convert to GSC findings."""
    findings: List[Finding] = []
    
    bumblebee = _find_bumblebee()
    if not bumblebee:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message="Bumblebee not installed. Install: go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest",
            fix_suggestion="Run: go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest",
            references=["https://github.com/perplexityai/bumblebee"],
        ))
        return findings

    try:
        # Run bumblebee on the project directory
        scan_dir = str(ctx.path) if getattr(ctx, "path", None) else os.getcwd()
        cmd = [
            bumblebee, "scan",
            "--profile", "baseline",
            "--root", scan_dir,
            "--emit-summary",
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PATH": os.environ.get("PATH", "") + ":/usr/local/go/bin"},
        )
        
        if result.returncode != 0:
            findings.append(Finding(
                rule_id=RULE_ID,
                severity="LOW",
                category=CATEGORY,
                echelon=ECHELON,
                file="N/A",
                line=0,
                message=f"Bumblebee scan failed: {result.stderr[:200]}",
                fix_suggestion="Check Bumblebee installation and permissions.",
                references=["https://github.com/perplexityai/bumblebee"],
            ))
            return findings

        # Parse JSON lines
        packages_by_eco: dict[str, list[dict]] = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            record_type = record.get("record_type", "")
            if record_type == "package":
                eco = record.get("ecosystem", "unknown")
                packages_by_eco.setdefault(eco, []).append(record)
            elif record_type == "scan_summary":
                summary = record
        
        # Report interesting ecosystems
        interesting = {"mcp", "editor-extension", "browser-extension", "agent-skill"}
        for eco, pkgs in sorted(packages_by_eco.items()):
            count = len(pkgs)
            if eco in interesting:
                for pkg in pkgs:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        severity="MEDIUM" if eco == "mcp" else "LOW",
                        category=CATEGORY,
                        echelon=ECHELON,
                        file=pkg.get("source_file", "N/A"),
                        line=0,
                        message=f"[{eco}] {pkg['package_name']}@{pkg.get('version', '?')} — {pkg.get('source_type', '?')}",
                        fix_suggestion=f"Review {eco} package: {pkg['package_name']}",
                        references=["https://github.com/perplexityai/bumblebee"],
                    ))
            else:
                # Summary for non-interesting ecosystems
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity="LOW",
                    category=CATEGORY,
                    echelon=ECHELON,
                    file=f"{scan_dir}/",
                    line=0,
                    message=f"[{eco}] {count} packages found (Bumblebee baseline scan)",
                    fix_suggestion="Review supply chain exposure. Use --exposure-catalog for threat intel matching.",
                    references=["https://github.com/perplexityai/bumblebee"],
                ))
        
        if not findings:
            findings.append(Finding(
                rule_id=RULE_ID,
                severity="INFO",
                category=CATEGORY,
                echelon=ECHELON,
                file="N/A",
                line=0,
                message="Bumblebee scan completed — no packages found.",
                fix_suggestion="",
            ))
            
    except subprocess.TimeoutExpired:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message="Bumblebee scan timed out (>30s).",
            fix_suggestion="Consider narrowing scan scope with --root or --ecosystem.",
        ))
    except Exception as e:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message=f"Bumblebee error: {e}",
            fix_suggestion="Check Bumblebee binary and Go installation.",
        ))

    return findings
