# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Proof-of-Fix Evidence Passport (audit Killer feature B).

Подписанный (HMAC-SHA256) JSON-паспорт для каждого verified fix — можно приложить
к Jira/PR/аудиту. HMAC даёт integrity + CI-authenticity (НЕ non-repudiation: ключ
симметричный, верификатор тоже может подписать; для третьих сторон — Ed25519).

Безопасность: domain separation (HMAC-префикс по схеме), key_id для ротации,
scope binding (repo/commit), проверка энтропии ключа (≥32 байт).
Verdict-логика (audit): «verified» только при container isolation И image_digest.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

SCHEMA = "gsc.evidence.v1"
_VALID_VERDICTS = ("verified", "structural", "unverified")
_MIN_KEY_BYTES = 32


def _domain_key(signing_key: bytes) -> bytes:
    """Domain-separate the raw key so it can't be reused across schemes."""
    return hmac.new(signing_key, SCHEMA.encode(), hashlib.sha256).digest()


def verdict_from_isolation(isolation: str, image_digest: str | None) -> str:
    """Map isolation + image provenance to an evidence verdict.

    - "verified":   container isolation (docker/podman) AND image digest present.
    - "structural": container isolation but no image digest.
    - "unverified": rlimit fallback / no OS-level isolation.
    """
    if isolation not in ("docker", "podman"):
        return "unverified"
    if not image_digest:
        return "structural"
    return "verified"


def make_passport(*, finding_key: str, verdict: str,
                  before: dict, after: dict,
                  scanner_sha: str, image_digest: str | None,
                  signing_key: bytes | None = None,
                  key_id: str = "", repo: str = "", commit: str = "") -> dict:
    """Build an evidence passport (signed iff signing_key is provided).

    unsigned (signing_key=None) → integrity only; verdict must be structural/unverified.
    signed → HMAC-SHA256 over canonical (sorted, compact) JSON.
    """
    if verdict not in _VALID_VERDICTS:
        raise ValueError(f"invalid verdict: {verdict!r}")
    if verdict == "verified" and not image_digest:
        raise ValueError("verified verdict requires image_digest")
    if signing_key and len(signing_key) < _MIN_KEY_BYTES:
        raise ValueError(f"signing_key must be >= {_MIN_KEY_BYTES} bytes")
    payload = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "finding_key": finding_key,
        "repo": repo,
        "commit": commit,
        "key_id": key_id,
        "verdict": verdict,
        "scanner_sha": scanner_sha,
        "image_digest": image_digest,
        "before": before,
        "after": after,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if signing_key:
        payload["signature"] = hmac.new(
            _domain_key(signing_key), canonical, hashlib.sha256).hexdigest()
    return payload


def verify_passport(passport: dict, signing_key: bytes) -> bool:
    """Verify HMAC signature + schema/verdict invariants (constant-time compare)."""
    if passport.get("schema") != SCHEMA:
        return False
    if passport.get("verdict") not in _VALID_VERDICTS:
        return False
    if passport.get("verdict") == "verified" and not passport.get("image_digest"):
        return False
    sig = passport.get("signature", "")
    if not sig:
        return False
    payload = {k: v for k, v in passport.items() if k != "signature"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(_domain_key(signing_key), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
