"""Shared fixtures for tollbooth tests."""

import sys
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
