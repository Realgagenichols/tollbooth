"""Tests for N2 OAuth: token storage, handlers, provider factory."""

import contextlib
import json
import socket
import stat
import threading
import time
import urllib.error
import urllib.request

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from tollbooth.config import OAuthConfig
from tollbooth.oauth import (
    FailClosedReauth,
    FileTokenStorage,
    OAuthFlowError,
    TokenStorageError,
    _failclosed_callback,
    _failclosed_redirect,
    _serve_loopback_callback,
    build_oauth_provider,
    oauth_storage_dir,
)

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

    async def test_loose_dir_permissions_rejected_in_strict_mode(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        store.path.parent.chmod(0o755)
        try:
            with pytest.raises(TokenStorageError, match="insecure permissions"):
                await store.get_tokens()
        finally:
            store.path.parent.chmod(0o700)

    async def test_symlink_store_rejected_in_strict_mode(self, tmp_path):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        # Replace the real file with a symlink to a 0600 file elsewhere.
        target = tmp_path / "elsewhere.json"
        target.write_text(store.path.read_text())
        target.chmod(0o600)
        store.path.unlink()
        store.path.symlink_to(target)
        with pytest.raises(TokenStorageError, match="symlink"):
            await store.get_tokens()

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


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fire(url: str, delay: float = 0.2) -> None:
    """Hit the loopback callback from a daemon thread after a short delay, so
    the awaited `_serve_loopback_callback` can propagate its own exception
    cleanly (no task-group ExceptionGroup wrapping)."""

    def _bg() -> None:
        time.sleep(delay)
        with contextlib.suppress(urllib.error.HTTPError, OSError):
            urllib.request.urlopen(url, timeout=5).close()

    threading.Thread(target=_bg, daemon=True).start()


class TestLoopbackCallback:
    async def test_returns_code_on_matching_state(self):
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/callback?code=the-code&state=xyz")
        code, state = await _serve_loopback_callback("xyz", port, timeout=5)
        assert code == "the-code"
        assert state == "xyz"

    async def test_state_mismatch_rejected_without_returning_code(self):
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/callback?code=the-code&state=WRONG")
        with pytest.raises(OAuthFlowError, match="state mismatch"):
            await _serve_loopback_callback("xyz", port, timeout=5)

    async def test_missing_code_rejected(self):
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/callback?state=xyz")
        with pytest.raises(OAuthFlowError, match="missing authorization code"):
            await _serve_loopback_callback("xyz", port, timeout=5)

    async def test_times_out_when_no_redirect(self):
        port = _free_port()
        with pytest.raises(OAuthFlowError, match="timed out"):
            await _serve_loopback_callback("xyz", port, timeout=0.5)

    async def test_no_expected_state_rejects_fail_closed(self):
        # Callback invoked before a state was captured (None) must reject, never
        # accept an unverifiable redirect.
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/callback?code=c&state=anything")
        with pytest.raises(OAuthFlowError, match="state mismatch"):
            await _serve_loopback_callback(None, port, timeout=5)

    async def test_non_callback_path_ignored(self):
        # A stray GET (favicon, probe) gets 404 and does NOT complete the flow.
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/favicon.ico")
        with pytest.raises(OAuthFlowError, match="timed out"):
            await _serve_loopback_callback("xyz", port, timeout=1.5)

    async def test_code_value_never_in_error_message(self):
        port = _free_port()
        _fire(f"http://127.0.0.1:{port}/callback?code=secret-code&state=BAD")
        with pytest.raises(OAuthFlowError) as excinfo:
            await _serve_loopback_callback("xyz", port, timeout=5)
        assert "secret-code" not in str(excinfo.value)


class TestProviderFactory:
    async def test_run_mode_wires_failclosed_and_strict_storage(self):
        provider = build_oauth_provider(
            "remote", "https://mcp.example.com/mcp", OAuthConfig(type="oauth"),
            interactive=False,
        )
        assert provider.context.redirect_handler is _failclosed_redirect
        assert provider.context.callback_handler is _failclosed_callback
        assert provider.context.storage.strict is True

    async def test_interactive_mode_wires_real_handlers_and_lenient_storage(self):
        provider = build_oauth_provider(
            "remote", "https://mcp.example.com/mcp",
            OAuthConfig(type="oauth", callback_port=9100), interactive=True,
        )
        assert provider.context.redirect_handler is not _failclosed_redirect
        assert provider.context.storage.strict is False
        assert str(provider.context.client_metadata.redirect_uris[0]) == (
            "http://127.0.0.1:9100/callback"
        )

    async def test_scopes_joined_into_metadata(self):
        provider = build_oauth_provider(
            "remote", "https://mcp.example.com/mcp",
            OAuthConfig(type="oauth", scopes=["mcp:read", "mcp:write"]),
            interactive=False,
        )
        assert provider.context.client_metadata.scope == "mcp:read mcp:write"

    async def test_failclosed_handlers_raise(self):
        with pytest.raises(FailClosedReauth):
            await _failclosed_redirect("https://auth.example/authorize")
        with pytest.raises(FailClosedReauth):
            await _failclosed_callback()

    async def test_token_expiry_computed_from_obtained_at(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())  # expires_in=3600
        expiry = store.token_expiry()
        assert expiry is not None
        assert abs(expiry - (time.time() + 3600)) < 60

    async def test_token_expiry_none_without_token(self):
        assert FileTokenStorage("nobody").token_expiry() is None

    async def test_provider_restores_token_expiry(self):
        store = FileTokenStorage("remote")
        await store.set_tokens(_token())
        provider = build_oauth_provider(
            "remote", "https://mcp.example.com/mcp", OAuthConfig(type="oauth"),
            interactive=False,
        )
        assert provider.context.token_expiry_time is not None
