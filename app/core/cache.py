"""Small shared Redis client for cross-pod application caches."""

from __future__ import annotations

import time

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


def rate_limited(key: str, limit: int, window: int) -> bool:
    """Return True when ``key`` has exceeded ``limit`` calls in ``window`` seconds.

    Sliding-window counter backed by a Redis sorted set: each call inserts a
    timestamp member, removes entries older than the window, and compares the
    set size to ``limit``. Fails open (returns False) when Redis is disabled or
    errors, so a cache outage never blocks requests.

    Args:
        key: Rate-limit bucket key (e.g. ``secretserver:rl:<token-hash>``).
        limit: Max allowed calls within the window.
        window: Sliding window length in seconds.

    Returns:
        True when the caller is over the limit; False otherwise.

    Example:
        >>> if rate_limited("secretserver:rl:abc", 100, 60):
        ...     return jsonify({"error": "rate limited"}), 429
    """
    client = redis_client()
    if client is None:
        return False
    now = time.time()
    min_score = now - window
    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, min_score)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window * 2)
        _, _, count, _ = pipe.execute()
        return count > limit
    except Exception:
        return False
