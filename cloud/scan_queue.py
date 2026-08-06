# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""Redis-очередь scan-задач. Просто и достаточно для S1."""
from __future__ import annotations

import json
import os
import redis

QUEUE_KEY = "gsc:scans"


class ScanQueue:
    def __init__(self, url: str | None = None):
        self._url = url
        self._r = None

    @property
    def r(self):
        if self._r is None:
            self._r = redis.from_url(self._url or os.environ["GSC_REDIS_URL"])
        return self._r

    def enqueue(self, job: dict) -> None:
        self.r.lpush(QUEUE_KEY, json.dumps(job))

    def dequeue(self, timeout: int = 10) -> dict | None:
        item = self.r.brpop(QUEUE_KEY, timeout=timeout)
        return json.loads(item[1]) if item else None