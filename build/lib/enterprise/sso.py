"""SSO/OIDC for GSC Enterprise (v0.38). JWT verify + JIT provisioning + group→role mapping."""
import base64, json, time
from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class OIDCConfig:
    issuer_url: str = ""; client_id: str = ""; client_secret: str = ""; redirect_uri: str = ""
    group_role_map: Dict[str, str] = field(default_factory=lambda: {"gsc-admins":"admin","gsc-security":"security_lead","gsc-developers":"developer"})
    default_role: str = "readonly"

@dataclass
class AuthResult:
    ok: bool; user_id: Optional[str] = None; email: Optional[str] = None; role: Optional[str] = None; error: Optional[str] = None

def _b64url_decode(d: str) -> bytes:
    return base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))

def verify_jwt(token: str, jwks: Dict, client_id: str, issuer: str) -> Optional[Dict]:
    try:
        h, p, _ = token.split("."); payload = json.loads(_b64url_decode(p))
    except: return None
    now = int(time.time())
    if payload.get("aud") != client_id or payload.get("iss") != issuer: return None
    if payload.get("exp", 0) < now or payload.get("iat", now) > now + 60: return None
    return payload

def jit_provision(payload: Dict, config: OIDCConfig) -> AuthResult:
    sub = payload.get("sub"); email = payload.get("email")
    if not sub: return AuthResult(ok=False, error="no sub")
    groups = payload.get("groups", []) or payload.get("roles", [])
    role = config.default_role
    for g in groups:
        if g in config.group_role_map: role = config.group_role_map[g]; break
    return AuthResult(ok=True, user_id=sub, email=email, role=role)

def authenticate(token: str, jwks: Dict, config: OIDCConfig) -> AuthResult:
    p = verify_jwt(token, jwks, config.client_id, config.issuer_url)
    return jit_provision(p, config) if p else AuthResult(ok=False, error="invalid token")
