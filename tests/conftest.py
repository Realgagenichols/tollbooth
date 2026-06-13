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


@pytest.fixture
def http_upstream_url():
    """Serve the in-repo streamable-HTTP MCP server on an ephemeral port.

    Yields the base MCP URL. A real uvicorn server in a background thread —
    no transport mocking, matching the project's real-subprocess bar.
    """
    import uvicorn

    from tests.http_echo_server import make_app

    # Bind an ephemeral port ourselves and hand the socket to uvicorn, so the
    # URL is known before the server starts (no port race).
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    config = uvicorn.Config(
        make_app().streamable_http_app(),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="on",  # runs the StreamableHTTP session-manager lifespan
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:  # pragma: no cover
            raise RuntimeError("http test server did not start within 10s")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
