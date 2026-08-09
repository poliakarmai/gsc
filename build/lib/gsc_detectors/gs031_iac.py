#!/usr/bin/env python3
"""GS031 — IaC misconfiguration detector (v0.34)."""
from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform, detect_ansible, _is_kubernetes
import re

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
        if file_path.endswith(".yml") or file_path.endswith(".yaml"):
            if _is_kubernetes(content):
                return detect_kubernetes(file_path, content)
            # Detect Ansible playbooks (hosts: or tasks: at top level)
            if re.search(r'^\s*(?:hosts|tasks|handlers|become)\s*:', content, re.MULTILINE):
                return detect_ansible(file_path, content)
        return []
