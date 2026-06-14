"""N2 integration: HttpUpstream against a real OAuth authorization server.

Drives the SDK's OAuthClientProvider end-to-end over HTTP (no flow mocking).
"""

import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.anyio


def _get_json(url: str):
    import json

    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def _get_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


class TestFakeAuthServerSmoke:
    async def test_metadata_documents_served(self, fake_oauth_server):
        base = fake_oauth_server.base_url
        status, prm = _get_json(f"{base}/.well-known/oauth-protected-resource")
        assert status == 200
        assert prm["authorization_servers"] == [base]
        status, asm = _get_json(f"{base}/.well-known/oauth-authorization-server")
        assert asm["token_endpoint"] == f"{base}/token"
        assert asm["registration_endpoint"] == f"{base}/register"

    async def test_mcp_endpoint_gated_401_without_token(self, fake_oauth_server):
        # No bearer → 401, which is what triggers the provider's OAuth flow.
        assert _get_status(fake_oauth_server.url) == 401
