#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC IaC v1.0 (v0.34) — Infrastructure as Code misconfiguration scanning.

Deterministic rules for Terraform / Kubernetes / Dockerfile.
No LLM → fork-safe. GS031.
"""

from __future__ import annotations

import hashlib, re
from typing import Dict, List


# ── Helpers ─────────────────────────────────────────────────
def _iac_finding(rule_id, severity, title, file_path, line_no, snippet, iac_type=""):
    finding_key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {"finding_key": finding_key, "rule_id": rule_id, "title": title,
            "severity": severity, "confidence": 0.85, "file": file_path,
            "line": line_no, "snippet": snippet,
            "metadata": {"iac": {"type": iac_type or _type_from_rule(rule_id)}}}


def _type_from_rule(rid): return "terraform" if "-TF-" in rid else "kubernetes" if "-K8S-" in rid else "dockerfile"
def _line(lines, n): return lines[n-1].strip() if 1 <= n <= len(lines) else ""
def _find(lines, needle):
    for i, l in enumerate(lines, 1):
        if needle in l: return i
    return 1


# ── Dockerfile ──────────────────────────────────────────────
DOCKER_RULES = [
    ("GS031-DOCKER-LATEST",  re.compile(r"^\s*FROM\s+\S+:latest\s*$", re.MULTILINE), "MEDIUM", "FROM :latest — unfixed image version"),
    ("GS031-DOCKER-SECRET-ENV", re.compile(r"^\s*(?:ENV|ARG)\s+(\w*(?:password|passwd|secret|key|token)\w*)\s*=?\s*\S+", re.MULTILINE | re.IGNORECASE), "HIGH", "Secret in ENV/ARG"),
    ("GS031-DOCKER-ADD-URL", re.compile(r"^\s*ADD\s+https?://", re.MULTILINE), "LOW", "ADD with URL — use COPY instead"),
    # 🆕 DevOps Book patterns
    ("GS031-DOCKER-LINT", re.compile(r"^\s*RUN\s+.*curl\s+.*\|\s*(?:sh|bash)", re.MULTILINE), "CRITICAL", "curl | sh — supply chain attack vector"),
    ("GS031-DOCKER-LINT-BINDS", re.compile(r"^\s*VOLUME\s+\[", re.MULTILINE), "LOW", "Unnamed VOLUME — use named volumes for persistence"),
]

def detect_dockerfile(file_path: str, content: str) -> List[dict]:
    findings = []
    lines = content.splitlines()
    for rid, pat, sev, title in DOCKER_RULES:
        for m in pat.finditer(content):
            n = content[:m.start()].count("\n") + 1
            findings.append(_iac_finding(rid, sev, title, file_path, n, _line(lines, n)))

    users = re.findall(r"^\s*USER\s+(\S+)", content, re.MULTILINE)
    if not users:
        findings.append(_iac_finding("GS031-DOCKER-NO-USER", "MEDIUM", "USER not set — container runs as root", file_path, 1, "(no USER)"))
    elif users[-1].lower() in ("root", "0"):
        ln = _find(lines, f"USER {users[-1]}")
        findings.append(_iac_finding("GS031-DOCKER-ROOT", "HIGH", f"USER {users[-1]} — runs as root", file_path, ln, f"USER {users[-1]}"))

    if re.search(r"^\s*FROM\s+", content, re.MULTILINE) and not re.search(r"^\s*HEALTHCHECK\s+", content, re.MULTILINE):
        findings.append(_iac_finding("GS031-DOCKER-NO-HEALTHCHECK", "LOW", "No HEALTHCHECK", file_path, 1, "(no HEALTHCHECK)"))
    return findings


# ── Kubernetes ──────────────────────────────────────────────
def _is_kubernetes(content: str) -> bool:
    return bool(re.search(r"^\s*kind:\s+", content, re.MULTILINE) and
                re.search(r"^\s*apiVersion:\s+", content, re.MULTILINE))

def _pod_spec(doc: dict) -> dict:
    if doc.get("kind") == "Pod": return doc.get("spec", {})
    return doc.get("spec", {}).get("template", {}).get("spec", {})

def detect_kubernetes(file_path: str, content: str) -> List[dict]:
    try:
        import yaml
        docs = list(yaml.safe_load_all(content))
    except Exception: return []
    findings = []
    for doc in docs:
        if not isinstance(doc, dict): continue
        if doc.get("kind") not in ("Pod","Deployment","StatefulSet","DaemonSet","Job","CronJob","ReplicaSet"): continue
        spec = _pod_spec(doc)
        if not spec: continue

        if spec.get("hostNetwork"): findings.append(_iac_finding("GS031-K8S-HOST-NETWORK","HIGH","hostNetwork: true",file_path,0,"hostNetwork: true"))
        if spec.get("hostPID"): findings.append(_iac_finding("GS031-K8S-HOST-PID","HIGH","hostPID: true",file_path,0,"hostPID: true"))
        if spec.get("hostIPC"): findings.append(_iac_finding("GS031-K8S-HOST-IPC","HIGH","hostIPC: true",file_path,0,"hostIPC: true"))

        for c in spec.get("containers",[]) + spec.get("initContainers",[]):
            name = c.get("name","container")
            sc = c.get("securityContext",{})
            if sc.get("privileged"): findings.append(_iac_finding("GS031-K8S-PRIVILEGED","CRITICAL",f"privileged: true in '{name}'",file_path,0,f"container: {name}, privileged: true"))
            if sc.get("runAsUser")==0: findings.append(_iac_finding("GS031-K8S-ROOT","HIGH",f"runAsUser: 0 in '{name}'",file_path,0,f"container: {name}, runAsUser: 0"))
            if "SYS_ADMIN" in sc.get("capabilities",{}).get("add",[]): findings.append(_iac_finding("GS031-K8S-CAP-SYS-ADMIN","CRITICAL",f"CAP_SYS_ADMIN in '{name}'",file_path,0,f"container: {name}, SYS_ADMIN"))
            if not c.get("resources",{}).get("limits"): findings.append(_iac_finding("GS031-K8S-NO-LIMITS","LOW",f"No resources.limits in '{name}'",file_path,0,f"container: {name}"))
            for p in c.get("ports",[]):
                if p.get("hostPort") and p["hostPort"]<1024: findings.append(_iac_finding("GS031-K8S-HOST-PORT","MEDIUM",f"hostPort {p['hostPort']} (<1024) in '{name}'",file_path,0,f"container: {name}, hostPort: {p['hostPort']}"))
            # 🆕 DevOps Book: probes
            if not c.get("livenessProbe"): findings.append(_iac_finding("GS031-K8S-NO-LIVENESS","LOW",f"No livenessProbe in '{name}' — K8s won't restart hung containers",file_path,0,f"container: {name}"))
            if not c.get("readinessProbe"): findings.append(_iac_finding("GS031-K8S-NO-READINESS","LOW",f"No readinessProbe in '{name}' — traffic goes to unready pods",file_path,0,f"container: {name}"))
    return findings


# ── Terraform ───────────────────────────────────────────────
TERRAFORM_RULES = [
    ("GS031-TF-SG-OPEN", re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', re.MULTILINE), "HIGH", "Security group open to 0.0.0.0/0"),
    ("GS031-TF-S3-PUBLIC-ACL", re.compile(r'acl\s*=\s*"(?:public-read|public-read-write)"', re.MULTILINE), "CRITICAL", "S3 bucket with public ACL"),
    ("GS031-TF-PUBLIC-IP", re.compile(r'associate_public_ip_address\s*=\s*true', re.MULTILINE), "MEDIUM", "Public IP on instance"),
    ("GS031-TF-PLAINTEXT-SECRET", re.compile(r'(?i)(?:access_key|secret_key|password)\s*=\s*"[^"]{8,}"'), "CRITICAL", "Hardcoded credentials in Terraform"),
    # 🆕 DevOps Book patterns
    ("GS031-TF-BACKEND-NO-ENCRYPT", re.compile(r'backend\s+"s3"\s*\{', re.MULTILINE), "HIGH", "S3 backend — verify encrypt=true is set (manual check)"),
    ("GS031-TF-RDS-PUBLIC", re.compile(r'publicly_accessible\s*=\s*true', re.MULTILINE), "CRITICAL", "RDS publicly accessible"),
    ("GS031-TF-IAM-WILDCARD", re.compile(r'"(?:arn:aws:[^"]*:\*|[^"]*\*[^"]*)"\s*\]', re.MULTILINE), "HIGH", "Wildcard in IAM resource ARN"),
    ("GS031-TF-S3-NO-VERSIONING", re.compile(r'bucket\s*=\s*"[^"]+"\s*\n', re.MULTILINE), "LOW", "S3 bucket — verify versioning is enabled (manual check)"),
]

def detect_terraform(file_path: str, content: str) -> List[dict]:
    findings = []
    lines = content.splitlines()
    for rid, pat, sev, title in TERRAFORM_RULES:
        for m in pat.finditer(content):
            n = content[:m.start()].count("\n") + 1
            findings.append(_iac_finding(rid, sev, title, file_path, n, _line(lines, n)))
    return findings


# ── Ansible ──────────────────────────────────────────────────
ANSIBLE_RULES = [
    ("GS031-ANSIBLE-VAULT", re.compile(r'(?i)(?:password|secret|token|api_key)\s*:\s*"[^"]{8,}"', re.MULTILINE), "CRITICAL", "Plaintext secret in Ansible — use ansible-vault"),
    ("GS031-ANSIBLE-SHELL", re.compile(r'^\s*shell:\s*curl\s+.*\|\s*(?:sh|bash)', re.MULTILINE), "CRITICAL", "curl | sh in Ansible — supply chain risk"),
    ("GS031-ANSIBLE-ROOT", re.compile(r'become:\s*yes', re.MULTILINE), "LOW", "become: yes — runs as root, use become_user"),
    ("GS031-ANSIBLE-NO-TAGS", re.compile(r'^---\s*\n(?!.*tags:\s*\[)', re.DOTALL), "LOW", "Playbook without tags — can't do partial runs"),
]


def detect_ansible(file_path: str, content: str) -> List[dict]:
    findings = []
    lines = content.splitlines()
    for rid, pat, sev, title in ANSIBLE_RULES:
        for m in pat.finditer(content):
            n = content[:m.start()].count("\n") + 1
            findings.append(_iac_finding(rid, sev, title, file_path, n, _line(lines, n), "ansible"))
    return findings
