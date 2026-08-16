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
