"""Политики сканирования из облака."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path


class PolicySync:
    def __init__(self, cloud_url: str, tenant_key: str):
        self.cloud_url = cloud_url.rstrip("/")
        self.tenant_key = tenant_key
        self.cache_path = Path.home() / ".gsc-agent/policy.json"

    def fetch(self) -> dict:
        try:
            req = urllib.request.Request(
                f"{self.cloud_url}/api/v2/agent/policy",
                headers={"Authorization":
                         f"Bearer {self.tenant_key}"},
                method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                policy = json.loads(resp.read())
            self._save(policy)
            return policy
        except Exception:
            return self._load_cached()

    def _save(self, policy: dict):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w") as f:
            json.dump(policy, f)

    def _load_cached(self) -> dict:
        if self.cache_path.exists():
            with open(self.cache_path) as f:
                return json.load(f)
        return {"profile": "audit"}