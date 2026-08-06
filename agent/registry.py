"""Регистрация агента в облаке через activation key."""
from __future__ import annotations

import json
import os
import urllib.request
import uuid


class AgentRegistry:
    def __init__(self, cloud_url: str, tenant_key: str):
        self.cloud_url = cloud_url.rstrip("/")
        self.tenant_key = tenant_key
        self.agent_uuid = self._load_or_create_uuid()
        self._session_token = None

    def _load_or_create_uuid(self) -> str:
        uuid_file = os.path.expanduser("~/.gsc-agent/agent_uuid")
        if os.path.exists(uuid_file):
            with open(uuid_file) as f:
                return f.read().strip()
        agent_uuid = str(uuid.uuid4())
        os.makedirs(os.path.dirname(uuid_file), exist_ok=True)
        with open(uuid_file, "w") as f:
            f.write(agent_uuid)
        return agent_uuid

    def activate(self) -> str:
        payload = json.dumps({
            "activation_key": self.tenant_key,
            "agent_uuid": self.agent_uuid,
            "version": "0.31",
        }).encode()
        req = urllib.request.Request(
            f"{self.cloud_url}/api/v2/agent/activate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        self._session_token = data["session_token"]
        return data["agent_id"]

    def ingest(self, payload: dict):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.cloud_url}/api/v2/agent/ingest",
            data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._session_token}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())