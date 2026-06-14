"""Shared fixtures for tollbooth tests."""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from tollbooth.config import StdioUpstreamConfig

ECHO_SERVER = Path(__file__).parent / "echo_server.py"


@pytest.fixture
def anyio_backend():
    # mcp SDK is anyio-based; run async tests on asyncio only.
    return "asyncio"


@pytest.fixture
def make_upstream_config():
    """Factory for upstream launch specs without touching real MCP servers.

    Defaults to the in-repo echo server subprocess; override `command`/`args`
    to simulate broken upstreams.
    """

    def _factory(**kwargs):
        defaults = {
            "command": sys.executable,
            "args": [str(ECHO_SERVER)],
            "env": {},
        }
        defaults.update(kwargs)
        return StdioUpstreamConfig.model_validate(defaults)

    return _factory


class _HttpTestServer:
    """A real uvicorn-served streamable-HTTP MCP server on an ephemeral port.

    No transport mocking — matches the project's real-subprocess bar. `stop()`
    shuts the server down mid-test so callers can exercise a dead-upstream path.
    """

    def __init__(self):
        import uvicorn

        from tests.http_echo_server import make_app

        # Bind an ephemeral port ourselves and hand the socket to uvicorn, so
        # the URL is known before the server starts (no port race).
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        self._server = uvicorn.Server(
            uvicorn.Config(
                make_app().streamable_http_app(),
                host="127.0.0.1",
                port=port,
                log_level="warning",
                lifespan="on",  # runs the StreamableHTTP session-manager lifespan
            )
        )
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:  # pragma: no cover
                raise RuntimeError("http test server did not start within 10s")
            time.sleep(0.02)

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture
def http_server():
    """Yield a running `_HttpTestServer` handle (`.url`, `.stop()`)."""
    server = _HttpTestServer()
    try:
        yield server
    finally:
        server.stop()


class _FakeOAuthServer:
    """A real uvicorn-served OAuth AS + protected MCP resource (N2 tests).

    Binds the socket first so `base_url` is known before the app (which embeds
    its own absolute endpoint URLs) is built. `.state` exposes counters/seeds.
    """

    def __init__(self):
        import uvicorn

        from tests.fake_oauth_server import FakeAuthState, build_fake_oauth_app

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{port}"
        self.url = f"{self.base_url}/mcp"
        self.state = FakeAuthState()
        self._server = uvicorn.Server(
            uvicorn.Config(
                build_fake_oauth_app(self.base_url, self.state),
                host="127.0.0.1",
                port=port,
                log_level="warning",
                lifespan="on",
            )
        )
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:  # pragma: no cover
                raise RuntimeError("fake oauth server did not start within 10s")
            time.sleep(0.02)

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture
def fake_oauth_server():
    """Yield a running `_FakeOAuthServer` (`.url`, `.base_url`, `.state`)."""
    server = _FakeOAuthServer()
    try:
        yield server
    finally:
        server.stop()
