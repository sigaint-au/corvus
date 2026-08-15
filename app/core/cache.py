"""Small shared Redis client for cross-pod application caches."""
from __future__ import annotations

import redis

from core.config import REDIS_URL

_client = None


def redis_client():
    """Return the lazy Redis client, or None when caching is disabled."""
    global _client
    if not REDIS_URL:
        return None
    if _client is None:
        _client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
    return _client
