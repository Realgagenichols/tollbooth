"""Tests for N2 OAuth: token storage, handlers, provider factory."""

import json
import stat

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from tollbooth.oauth import FileTokenStorage, TokenStorageError, oauth_storage_dir

pytestmark = pytest.mark.anyio

SENTINEL_ACCESS = "sentinel-access-token-DO-NOT-LEAK"
SENTINEL_REFRESH = "sentinel-refresh-token-DO-NOT-LEAK"


@pytest.fixture(autouse=True)
def _xdg(tmp_path, monkeypatch):
    """Point the OAuth store at a tmp dir for every test."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    return tmp_path


def _token() -> OAuthToken:
    return OAuthToken(
        access_token=SENTINEL_ACCESS,
        token_type="Bearer",
        expires_in=3600,
        refresh_token=SENTINEL_REFRESH,
        scope="mcp:read",
    )


def _client_info() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="client-abc",
        client_secret="sentinel-client-secret",
        redirect_uris=["http://127.0.0.1:8765/callback"],
    )


class TestStorageRoundTrip:
    async def test_round_trip_tokens_and_client_info(self):
        store = FileTokenStorage("remote")
        await store.set_client_info(_client_info())
        await store.set_tokens(_token())

        fresh = FileTokenStorage("remote")
        tok = await fresh.get_tokens()
        ci = await fresh.get_client_info()
        assert tok.access_token == SENTINEL_ACCESS
        assert tok.refresh_token == SENTINEL_REFRESH
        assert ci.client_id == "client-abc"
        assert ci.client_secret == "sentinel-client-secret"

    async def test_absent_store_returns_none(self):
        store = FileTokenStorage("nobody")
        assert await store.get_tokens() is None
        assert await store.get_client_info() is None

    async def test_file_and_dir_have_locked_down_permissions(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700

    async def test_obtained_at_recorded(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        doc = json.loads(store.path.read_text())
        assert doc["obtained_at"] is not None


class TestStorageRejection:
    async def test_loose_permissions_rejected_in_strict_mode(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        store.path.chmod(0o644)
        with pytest.raises(TokenStorageError, match="insecure permissions"):
            await store.get_tokens()

    async def test_loose_permissions_ignored_when_not_strict(self):
        FileTokenStorage("remote")  # create dir
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        store.path.chmod(0o644)
        lenient = FileTokenStorage("remote", strict=False)
        assert await lenient.get_tokens() is None  # treated as absent

    async def test_malformed_json_rejected_in_strict_mode(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())  # establishes the dir at 0700
        store.path.write_text("{not json")
        store.path.chmod(0o600)
        with pytest.raises(TokenStorageError, match="unreadable"):
            await store.get_tokens()

    async def test_path_traversal_name_rejected(self):
        with pytest.raises(TokenStorageError, match="not a valid credential filename"):
            FileTokenStorage("../escape")


class TestStorageSecretHygiene:
    async def test_sentinel_never_in_rejection_message(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        store.path.chmod(0o604)
        with pytest.raises(TokenStorageError) as excinfo:
            await store.get_tokens()
        assert SENTINEL_ACCESS not in str(excinfo.value)
        assert SENTINEL_REFRESH not in str(excinfo.value)

    async def test_describe_returns_no_token_values(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        info = store.describe()
        assert info["expires_in"] == 3600
        assert info["has_refresh_token"] is True
        assert SENTINEL_ACCESS not in json.dumps(info)
        assert SENTINEL_REFRESH not in json.dumps(info)

    async def test_delete_removes_file(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        assert store.delete() is True
        assert store.delete() is False
        assert await store.get_tokens() is None


def test_storage_dir_honors_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "custom"))
    assert oauth_storage_dir() == tmp_path / "custom" / "tollbooth" / "oauth"
