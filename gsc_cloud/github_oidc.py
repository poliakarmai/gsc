#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GSC GitHub OIDC Worker Auth.

Replaces long-lived installation tokens with AWS STS temporary credentials
via OIDC (OpenID Connect). Worker assumes IAM role through GitHub Actions
OIDC provider — no secrets in CI variables, tokens expire in 15-60 minutes.

Flow:
  GitHub Actions → OIDC JWT → AWS STS AssumeRoleWithWebIdentity
    → temporary AWS creds → S3/Secrets Manager/DynamoDB access

Ref: Brikman "Fundamentals of DevOps", ch.5 (CI/CD — OIDC over tokens).
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional


# ── OIDC Token ────────────────────────────────────────────────────────

def get_oidc_token(audience: str = "sts.amazonaws.com") -> str:
    """Request OIDC token from GitHub Actions. Only works inside GHA runner."""
    token = _get_actions_oidc_token(audience)
    if not token:
        # Fallback: try env variable (for local testing)
        token = os.environ.get("GSC_OIDC_TOKEN", "")
    if not token:
        raise RuntimeError(
            "OIDC token not available. Run inside GitHub Actions with "
            "permissions.id-token: write, or set GSC_OIDC_TOKEN for local testing."
        )
    return token


def _get_actions_oidc_token(audience: str) -> Optional[str]:
    """Get OIDC token from GitHub Actions runtime."""
    token_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    token_runtime = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

    if not token_url or not token_runtime:
        return None

    import urllib.request

    req = urllib.request.Request(
        f"{token_url}&audience={audience}",
        headers={
            "Authorization": f"bearer {token_runtime}",
            "Accept": "application/json; api-version=2.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("value", "")
    except Exception:
        return None


# ── AWS STS ────────────────────────────────────────────────────────────

def assume_role_with_oidc(
    role_arn: str,
    session_name: str = "gsc-worker",
    duration: int = 3600,
    region: str = "us-east-1",
) -> dict:
    """
    Exchange OIDC token for temporary AWS credentials.

    Returns: {
        "AccessKeyId": "...",
        "SecretAccessKey": "...",
        "SessionToken": "...",
        "Expiration": "2026-08-08T05:00:00Z"
    }
    """
    import urllib.request

    token = get_oidc_token()

    body = json.dumps({
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "WebIdentityToken": token,
        "DurationSeconds": min(duration, 43200),  # max 12 hours
    }).encode()

    req = urllib.request.Request(
        "https://sts.amazonaws.com/",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    # AWS STS expects form-encoded body
    import urllib.parse
    params = urllib.parse.urlencode({
        "Action": "AssumeRoleWithWebIdentity",
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "WebIdentityToken": token,
        "DurationSeconds": str(duration),
        "Version": "2011-06-15",
    }).encode()

    req = urllib.request.Request(
        "https://sts.amazonaws.com/",
        data=params,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            # Parse XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.read())
            ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
            creds = root.find(".//s:Credentials", ns)
            if creds is None:
                raise RuntimeError(f"STS response missing Credentials: {ET.tostring(root).decode()}")

            return {
                "AccessKeyId": creds.findtext("s:AccessKeyId", "", ns),
                "SecretAccessKey": creds.findtext("s:SecretAccessKey", "", ns),
                "SessionToken": creds.findtext("s:SessionToken", "", ns),
                "Expiration": creds.findtext("s:Expiration", "", ns),
            }
    except Exception as e:
        raise RuntimeError(f"AWS STS AssumeRoleWithWebIdentity failed: {e}")


# ── Token Cache ────────────────────────────────────────────────────────

class OIDCTokenCache:
    """Cache AWS credentials until expiry (avoid re-auth on every call)."""

    def __init__(self):
        self._creds: Optional[dict] = None
        self._expiry: float = 0
        self._margin: int = 300  # refresh 5 minutes before expiry

    def get_credentials(self, role_arn: str, session_name: str = "gsc-worker") -> dict:
        if self._creds and time.time() < (self._expiry - self._margin):
            return self._creds

        self._creds = assume_role_with_oidc(role_arn, session_name)
        # Parse ISO timestamp to Unix
        exp_str = self._creds.get("Expiration", "")
        try:
            from datetime import datetime
            self._expiry = datetime.fromisoformat(exp_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            self._expiry = time.time() + 3600  # safe default
        return self._creds

    def invalidate(self):
        self._creds = None
        self._expiry = 0


_oidc_cache = OIDCTokenCache()


# ── GitHub API with OIDC ──────────────────────────────────────────────

def gh_headers_oidc(role_arn: str = "") -> dict:
    """Get GitHub API headers using OIDC-derived token."""
    # For GitHub access, we still need a GitHub token.
    # OIDC is for AWS resources (S3, Secrets Manager).
    # GitHub token can be fetched from Secrets Manager using AWS creds.
    return gh_token_from_secrets_manager(role_arn)


def gh_token_from_secrets_manager(role_arn: str, secret_id: str = "gsc/github-app-key") -> str:
    """
    Fetch GitHub token from AWS Secrets Manager using OIDC credentials.
    This eliminates long-lived tokens in CI variables.
    """
    creds = _oidc_cache.get_credentials(role_arn)

    # Use boto3 or aws CLI to fetch secret
    import subprocess
    env = os.environ.copy()
    env.update({
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    })

    try:
        result = subprocess.run(
            ["aws", "secretsmanager", "get-secret-value",
             "--secret-id", secret_id, "--query", "SecretString", "--output", "text"],
            capture_output=True, text=True, timeout=15, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Secrets Manager error: {result.stderr[:200]}")

        secret = json.loads(result.stdout.strip())
        # Generate GitHub App installation token from private key
        return _github_app_token(secret.get("app_id", ""), secret.get("private_key", ""))
    except Exception as e:
        raise RuntimeError(f"Failed to fetch GitHub token via OIDC: {e}")


def _github_app_token(app_id: str, private_key: str) -> str:
    """Generate GitHub App installation token from private key."""
    import jwt
    import time

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,  # 10 minutes max per GitHub
        "iss": app_id,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")

    import urllib.request
    req = urllib.request.Request(
        "https://api.github.com/app/installations",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "GSC-OIDC/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        installations = json.loads(resp.read())

    if not installations:
        raise RuntimeError("No GitHub App installations found")

    installation_id = installations[0]["id"]
    access_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    req2 = urllib.request.Request(
        access_url, method="POST",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req2, timeout=10) as resp2:
        access = json.loads(resp2.read())
        return access["token"]


# ── CLI ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 github_oidc.py <role-arn> [session-name]")
        print("  Fetches AWS creds via OIDC and GitHub token from Secrets Manager")
        sys.exit(1)

    role_arn = sys.argv[1]
    session = sys.argv[2] if len(sys.argv) > 2 else "gsc-worker"

    try:
        token = gh_token_from_secrets_manager(role_arn)
        print(f"✓ GitHub token obtained ({len(token)} chars)")
        print(f"  Token prefix: {token[:10]}...")
    except Exception as e:
        print(f"✗ Failed: {e}")
        sys.exit(1)
