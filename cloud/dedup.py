"""Delivery dedup через Redis SETNX (S2).

Повторная доставка того же X-GitHub-Delivery игнорируется.
TTL 24ч — окно replay-защиты.
"""
import os
import redis


class DeliveryDedup:
    """SETNX с TTL: повторная доставка того же delivery игнорируется."""

    def __init__(self):
        self._url = os.environ.get("GSC_REDIS_URL", "")
        self._r = None

    @property
    def r(self):
        if self._r is None:
            self._r = redis.from_url(self._url)
        return self._r

    def once(self, key: str, ttl: int) -> bool:
        return bool(self.r.set(key, "1", nx=True, ex=ttl))