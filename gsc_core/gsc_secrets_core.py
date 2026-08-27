"""Single source for secrets detection — patterns + fingerprint (refactor #2).

Used by BOTH: GS029 detector + gsc_crossrepo_secrets correlation.
Same fingerprint = same cross-repo correlation.
"""
import hashlib
import math
import re
from typing import Dict, List

PATTERNS: List[tuple] = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", None, 0.0),
    (re.compile(r'-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY'), "private_key", None, 0.0),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "jwt_token", None, 0.0),
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\'\"]?([A-Za-z0-9+/=_.\-]{12,})'),
     "config_secret", 1, 3.0),
    (re.compile(r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s\'\"]{10,}'), "db_url", None, 0.0),
    (re.compile(r'(?i)(?:secret|key|token|password|hash)\s*[:=]\s*[\'\"]?[0-9a-fA-F]{32,64}'),
     "hex_key", None, 3.0),
]

def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

def fingerprint_secret(value: str) -> str:
    return hashlib.sha256(value.strip().strip("'\"'").encode()).hexdigest()[:32]

def extract_secrets(content: str, file_path: str, include_value: bool = False) -> List[Dict]:
    """Извлечь секреты. При include_value=True добавляет 'value' в память
    (для live-verify Фазы 8) — значение НЕ персистится, только fingerprint."""
    found = []
    for pattern, stype, cap_idx, min_ent in PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(cap_idx) if cap_idx else m.group(0)
            if min_ent > 0 and entropy(value) < min_ent: continue
            item = {"secret_type": stype, "file_path": file_path,
                    "line_number": content[:m.start()].count("\n")+1,
                    "fingerprint": fingerprint_secret(value)}
            if include_value:
                item["value"] = value
            found.append(item)
    return found
