#!/usr/bin/env python3
"""GS031 — IaC misconfiguration detector (v0.34)."""
from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform, _is_kubernetes

class GS031IaCDetector:
    rule_id = "GS031"
    name = "Infrastructure as Code Misconfigurations"
    requires_llm = False

    def detect(self, file_path, content, language="auto"):
        if file_path.endswith(".tf") or file_path.endswith(".tfvars"):
            return detect_terraform(file_path, content)
        base = file_path.split("/")[-1].lower()
        if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
            return detect_dockerfile(file_path, content)
        if file_path.endswith((".yaml", ".yml")) and _is_kubernetes(content):
            return detect_kubernetes(file_path, content)
        return []
