"""N2 integration: HttpUpstream against a real OAuth authorization server.

Drives the SDK's OAuthClientProvider end-to-end over HTTP (no flow mocking).
"""

import contextlib
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.anyio


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _simulate_browser(monkeypatch, delay=0.3):
    """Replace webbrowser.open with a thread that GETs the authorize URL and
    follows the 302 to the loopback callback — the test's stand-in for a user
    approving in a browser. The delay lets the loopback server bind first."""
    from tollbooth import oauth

    def _open(url, *a, **k):
        def _bg():
            time.sleep(delay)
            with contextlib.suppress(Exception):
                urllib.request.urlopen(url, timeout=5).close()

        threading.Thread(target=_bg, daemon=True).start()
        return True

    monkeypatch.setattr(oauth.webbrowser, "open", _open)


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


def _no_browser(monkeypatch):
    from tollbooth import oauth

    monkeypatch.setattr(
        oauth.webbrowser, "open", lambda *a, **k: pytest.fail("browser opened")
    )


class TestRunMode:
    async def test_fails_closed_when_no_token(
        self, fake_oauth_server, tmp_path, monkeypatch
    ):
        """N2: no usable token → origin-only error pointing at `auth login`,
        no browser, no secret leak. A sibling stdio upstream still works."""
        from tollbooth.config import HttpUpstreamConfig, OAuthConfig
        from tollbooth.upstream import HttpUpstream, UpstreamError

        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _no_browser(monkeypatch)

        config = HttpUpstreamConfig(
            url=fake_oauth_server.url, auth=OAuthConfig(type="oauth")
        )
        upstream = HttpUpstream("remote", config, init_timeout=15)
        with pytest.raises(UpstreamError) as excinfo:
            await upstream.start()
        await upstream.aclose()
        message = str(excinfo.value)
        assert "tollbooth auth login remote" in message
        assert fake_oauth_server.base_url in message  # origin only
        assert "/mcp" not in message  # path stripped
        # The full authorize URL (state + PKCE) must not have leaked.
        assert "code_challenge" not in message and "state=" not in message

    async def test_sibling_stdio_upstream_unaffected(
        self, fake_oauth_server, make_upstream_config, tmp_path, monkeypatch
    ):
        """R1/R4: a fail-closed OAuth upstream doesn't break a stdio sibling."""
        from tollbooth.config import HttpUpstreamConfig, OAuthConfig
        from tollbooth.upstream import HttpUpstream, StdioUpstream, UpstreamError

        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _no_browser(monkeypatch)

        oauth_up = HttpUpstream(
            "remote",
            HttpUpstreamConfig(url=fake_oauth_server.url, auth=OAuthConfig(type="oauth")),
            init_timeout=15,
        )
        with pytest.raises(UpstreamError):
            await oauth_up.start()
        await oauth_up.aclose()

        stdio = StdioUpstream("fs", make_upstream_config())
        await stdio.start()
        try:
            result = await stdio.call_tool("echo", {"text": "hi"})
            assert result.content[0].text == "echo: hi"
        finally:
            await stdio.aclose()

    async def test_refreshes_expired_token_silently(
        self, fake_oauth_server, tmp_path, monkeypatch
    ):
        """N2: an expired token with a usable refresh token refreshes without a
        browser; the call succeeds and the refreshed token is persisted."""
        import json
        import time
        from datetime import UTC, datetime

        from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

        from tollbooth.config import HttpUpstreamConfig, OAuthConfig
        from tollbooth.oauth import FileTokenStorage
        from tollbooth.upstream import HttpUpstream

        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _no_browser(monkeypatch)

        refresh_token = "rt-seeded-refresh"
        fake_oauth_server.state.issued_refresh_tokens.add(refresh_token)

        store = FileTokenStorage("remote")
        await store.set_client_info(
            OAuthClientInformationFull(
                client_id="seeded-client",
                redirect_uris=["http://127.0.0.1:8765/callback"],
            )
        )
        await store.set_tokens(
            OAuthToken(
                access_token="at-expired",
                token_type="Bearer",
                expires_in=1,
                refresh_token=refresh_token,
            )
        )
        # Backdate so token_expiry() is in the past → forces a refresh.
        doc = json.loads(store.path.read_text())
        doc["obtained_at"] = datetime.fromtimestamp(time.time() - 3600, UTC).isoformat()
        store.path.write_text(json.dumps(doc))
        store.path.chmod(0o600)

        config = HttpUpstreamConfig(
            url=fake_oauth_server.url, auth=OAuthConfig(type="oauth")
        )
        upstream = HttpUpstream("remote", config, init_timeout=15)
        try:
            await upstream.start()
            result = await upstream.call_tool("echo", {"text": "hi"})
            assert result.content[0].text == "echo: hi"
        finally:
            await upstream.aclose()

        assert fake_oauth_server.state.refresh_grants == 1
        # The refreshed access token was persisted (no longer the expired one).
        refreshed = await FileTokenStorage("remote").get_tokens()
        assert refreshed.access_token != "at-expired"
        assert refreshed.access_token in fake_oauth_server.state.issued_access_tokens


class TestInteractiveLogin:
    async def test_login_persists_token(self, fake_oauth_server, tmp_path, monkeypatch):
        """N2: `auth login` completes the auth-code+PKCE flow via the loopback
        callback and persists a working token."""
        from tollbooth.config import OAuthConfig
        from tollbooth.oauth import FileTokenStorage, perform_login

        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _simulate_browser(monkeypatch)

        config = OAuthConfig(type="oauth", callback_port=_free_port())
        await perform_login("remote", fake_oauth_server.url, config)

        assert fake_oauth_server.state.code_grants == 1
        stored = await FileTokenStorage("remote").get_tokens()
        assert stored is not None
        assert stored.access_token in fake_oauth_server.state.issued_access_tokens
        # The registered client was persisted too (reused on re-login).
        assert (await FileTokenStorage("remote").get_client_info()) is not None


class TestSecretHygiene:
    async def test_sentinel_token_never_in_our_logs_or_errors(
        self, fake_oauth_server, tmp_path, monkeypatch, caplog
    ):
        """N2: a sentinel refresh token used on the run path never appears in
        tollbooth's logs or any raised error (it rides the wire to /token only)."""
        import json as _json
        import logging
        from datetime import UTC, datetime

        from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

        from tollbooth.config import HttpUpstreamConfig, OAuthConfig
        from tollbooth.oauth import FileTokenStorage
        from tollbooth.upstream import HttpUpstream

        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _no_browser(monkeypatch)

        sentinel = "rt-SENTINEL-DO-NOT-LOG"
        fake_oauth_server.state.issued_refresh_tokens.add(sentinel)
        store = FileTokenStorage("remote")
        await store.set_client_info(
            OAuthClientInformationFull(
                client_id="c", redirect_uris=["http://127.0.0.1:8765/callback"]
            )
        )
        await store.set_tokens(
            OAuthToken(
                access_token="at-x", token_type="Bearer", expires_in=1,
                refresh_token=sentinel,
            )
        )
        doc = _json.loads(store.path.read_text())
        doc["obtained_at"] = datetime.fromtimestamp(0, UTC).isoformat()
        store.path.write_text(_json.dumps(doc))
        store.path.chmod(0o600)

        upstream = HttpUpstream(
            "remote",
            HttpUpstreamConfig(url=fake_oauth_server.url, auth=OAuthConfig(type="oauth")),
            init_timeout=15,
        )
        with caplog.at_level(logging.INFO, logger="tollbooth"):
            await upstream.start()
            await upstream.call_tool("echo", {"text": "hi"})
            await upstream.aclose()
        assert sentinel not in caplog.text
