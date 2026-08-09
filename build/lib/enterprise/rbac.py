"""RBAC for GSC Enterprise (v0.38). Roles → permissions, fail-closed."""
from typing import Dict, Set

PERMISSIONS = {"scan","view_findings","verdict","override","manage_policy","manage_users","view_audit","export","manage_tenant"}
ROLES: Dict[str, Set[str]] = {
    "admin": set(PERMISSIONS),
    "security_lead": {"scan","view_findings","verdict","override","manage_policy","view_audit","export"},
    "developer": {"scan","view_findings","verdict"},
    "auditor": {"view_findings","view_audit","export"},
    "readonly": {"view_findings"},
}

def can(role: str, action: str) -> bool:
    perms = ROLES.get(role); return action in perms if perms else False
