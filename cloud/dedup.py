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

    def once_raw(self, key: str, ttl: int, value: str = "pending") -> bool:
        """SETNX с произвольным значением (для OAuth state)."""
        return bool(self.r.set(key, value, nx=True, ex=ttl))

    def consume(self, key: str) -> bool:
        """GETDEL: одноразовое потребление ключа (state для OAuth)."""
        return self.r.getdel(key) is not None