"""Delivery dedup через Redis SETNX (S2).

Повторная доставка того же X-GitHub-Delivery игнорируется.
TTL 24ч — окно replay-защиты.
"""
import os
import redis


class DeliveryDedup:
    """SETNX с TTL: повторная доставка того же delivery игнорируется."""

    def __init__(self):
        self.r = redis.from_url(os.environ["GSC_REDIS_URL"])

    def once(self, key: str, ttl: int) -> bool:
        return bool(self.r.set(key, "1", nx=True, ex=ttl))