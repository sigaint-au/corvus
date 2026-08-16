"""OIDC shared-cache tests."""
from unittest.mock import MagicMock, patch

from integrations import oidc_auth


def test_discover_uses_redis_cache():
    """Discovery documents are shared between application replicas."""
    client = MagicMock()
    client.get.side_effect = ["0", None]
    document = {
        "authorization_endpoint": "https://idp/auth",
        "token_endpoint": "https://idp/token",
    }
    with patch.object(oidc_auth.cache, "redis_client", return_value=client), \
         patch.object(oidc_auth, "_http_json", return_value=document) as fetch:
        assert oidc_auth.discover("https://idp") == document
    fetch.assert_called_once()
    client.setex.assert_called_once()


def test_clear_discovery_cache_advances_shared_epoch():
    """OIDC settings changes invalidate discovery data across replicas."""
    client = MagicMock()
    with patch.object(oidc_auth.cache, "redis_client", return_value=client):
        oidc_auth.clear_discovery_cache()
    client.incr.assert_called_once_with("secretserver:oidc:discovery:epoch")


def test_rate_limited_sliding_window():
    """Rate limiter trips above the limit and fails open without Redis."""
    from core import cache

    def pipe_with(count):
        client = MagicMock()
        client.pipeline.return_value = client  # execute on the same mock
        client.execute.return_value = [1, 1, count, 60]
        return client

    with patch.object(cache, "redis_client", return_value=pipe_with(5)):
        assert cache.rate_limited("secretserver:rl:x", limit=10, window=60) is False
    with patch.object(cache, "redis_client", return_value=pipe_with(11)):
        assert cache.rate_limited("secretserver:rl:x", limit=10, window=60) is True
    with patch.object(cache, "redis_client", return_value=None):
        assert cache.rate_limited("secretserver:rl:x", limit=10, window=60) is False
