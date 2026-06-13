"""Tests for R1: upstream transport (stdio lifecycle, discovery, forwarding).

N1 adds streamable-HTTP upstream coverage (TestHttpUpstream).
"""

import sys

import pytest

from tollbooth.upstream import StdioUpstream, UpstreamError

pytestmark = pytest.mark.anyio


async def test_lists_tools(make_upstream_config):
    upstream = StdioUpstream("echo", make_upstream_config())
    try:
        await upstream.start()
        tools = await upstream.list_tools()
        assert {t.name for t in tools} == {"echo", "shout", "leak"}
    finally:
        await upstream.aclose()


async def test_forwards_tool_call(make_upstream_config):
    upstream = StdioUpstream("echo", make_upstream_config())
    try:
        await upstream.start()
        result = await upstream.call_tool("echo", {"text": "hi"})
        assert result.isError is False
        assert result.content[0].text == "echo: hi"
    finally:
        await upstream.aclose()


async def test_call_after_aclose_raises_not_running(make_upstream_config):
    """Section 7's dies-mid-session handling relies on this error path."""
    upstream = StdioUpstream("echo", make_upstream_config())
    await upstream.start()
    await upstream.aclose()
    with pytest.raises(UpstreamError, match="not running"):
        await upstream.call_tool("echo", {"text": "hi"})


async def test_double_start_rejected(make_upstream_config):
    """A second start() must not orphan the first subprocess."""
    upstream = StdioUpstream("echo", make_upstream_config())
    try:
        await upstream.start()
        with pytest.raises(UpstreamError, match="already running"):
            await upstream.start()
    finally:
        await upstream.aclose()


# R1 scenario: upstream server fails to start
async def test_missing_command_raises_clear_error(make_upstream_config):
    upstream = StdioUpstream(
        "ghost", make_upstream_config(command="/nonexistent/cmd-xyz", args=[])
    )
    try:
        with pytest.raises(UpstreamError, match="ghost"):
            await upstream.start()
    finally:
        await upstream.aclose()


# R1 scenario: process exits before initialization completes — no hang
async def test_command_exiting_early_raises_named_error(make_upstream_config):
    upstream = StdioUpstream(
        "flaky",
        make_upstream_config(command=sys.executable, args=["-c", "import sys; sys.exit(1)"]),
        init_timeout=5,
    )
    try:
        with pytest.raises(UpstreamError, match="flaky"):
            await upstream.start()
    finally:
        await upstream.aclose()


# --- N1: streamable HTTP upstream --------------------------------------------


async def test_http_fixture_smoke(http_server):
    """The HTTP test server fixture serves a real, initializable MCP endpoint."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with (
        streamable_http_client(http_server.url) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.list_tools()
    assert {t.name for t in result.tools} == {"echo", "leak", "echo_header", "slow"}


def _http_config(url, headers=None):
    from tollbooth.config import HttpUpstreamConfig

    return HttpUpstreamConfig.model_validate({"url": url, "headers": headers or {}})


async def test_http_pass_through(http_server):
    """N1: list + forward a tool call over streamable HTTP."""
    from tollbooth.upstream import HttpUpstream

    upstream = HttpUpstream("remote", _http_config(http_server.url))
    try:
        await upstream.start()
        tools = await upstream.list_tools()
        assert {t.name for t in tools} == {"echo", "leak", "echo_header", "slow"}
        result = await upstream.call_tool("echo", {"text": "hi"})
        assert result.isError is False
        assert result.content[0].text == "echo: hi"
    finally:
        await upstream.aclose()


async def test_http_header_env_expansion(http_server, monkeypatch):
    """N1: ${ENV_VAR} in a header is resolved and reaches the server."""
    from tollbooth.upstream import HttpUpstream

    monkeypatch.setenv("REMOTE_TOKEN", "s3cr3t-token-value")
    upstream = HttpUpstream(
        "remote",
        _http_config(http_server.url, {"X-Auth": "Bearer ${REMOTE_TOKEN}"}),
    )
    try:
        await upstream.start()
        result = await upstream.call_tool("echo_header", {"name": "x-auth"})
        assert result.content[0].text == "Bearer s3cr3t-token-value"
    finally:
        await upstream.aclose()


async def test_http_missing_env_var_fails_closed_without_echo(http_server, monkeypatch):
    """N1: an unset ${VAR} fails closed naming server + var, never the value."""
    from tollbooth.upstream import HttpUpstream

    monkeypatch.delenv("REMOTE_TOKEN", raising=False)
    upstream = HttpUpstream(
        "remote",
        _http_config(http_server.url, {"X-Auth": "Bearer ${REMOTE_TOKEN}"}),
    )
    try:
        with pytest.raises(UpstreamError) as excinfo:
            await upstream.start()
        message = str(excinfo.value)
        assert "remote" in message and "REMOTE_TOKEN" in message
        assert "Bearer" not in message  # the header value never appears
    finally:
        await upstream.aclose()


async def test_http_error_sanitizes_url_credentials():
    """N1: errors echo only the origin — never userinfo, path, or query."""
    from tollbooth.upstream import HttpUpstream

    # Unreachable port; URL carries userinfo + a token query param.
    url = "http://user:pa55w0rd@127.0.0.1:1/secret/path?token=qsecret123"
    upstream = HttpUpstream("remote", _http_config(url), init_timeout=2)
    try:
        with pytest.raises(UpstreamError) as excinfo:
            await upstream.start()
        message = str(excinfo.value)
        assert "http://127.0.0.1:1" in message
        for leaked in ("user", "pa55w0rd", "secret/path", "qsecret123", "token="):
            assert leaked not in message
    finally:
        await upstream.aclose()


async def test_http_double_start_rejected(http_server):
    from tollbooth.upstream import HttpUpstream

    upstream = HttpUpstream("remote", _http_config(http_server.url))
    try:
        await upstream.start()
        with pytest.raises(UpstreamError, match="already running"):
            await upstream.start()
    finally:
        await upstream.aclose()


async def test_http_call_after_aclose_raises_not_running(http_server):
    from tollbooth.upstream import HttpUpstream

    upstream = HttpUpstream("remote", _http_config(http_server.url))
    await upstream.start()
    await upstream.aclose()
    with pytest.raises(UpstreamError, match="not running"):
        await upstream.call_tool("echo", {"text": "hi"})


async def test_http_external_cancellation_propagates():
    """N1: a genuine external cancel during start() must NOT become UpstreamError.

    Distinguishes real cancellation from a transport connection failure (which
    is also a cancellation internally but carries a concrete cause).
    """
    import anyio

    from tollbooth.upstream import HttpUpstream

    # A port that black-holes the connect so start() is mid-initialize when the
    # surrounding scope cancels it (10.255.255.1 is non-routable → hangs).
    upstream = HttpUpstream(
        "remote", _http_config("http://10.255.255.1:9/mcp"), init_timeout=30
    )
    cancelled = False
    try:
        with anyio.move_on_after(0.3) as scope:
            await upstream.start()
        cancelled = scope.cancelled_caught
    finally:
        await upstream.aclose()
    # The external cancel was honored (scope caught it) — start() did not swallow
    # it into an UpstreamError.
    assert cancelled is True


async def test_http_aclose_does_not_block_on_in_flight_call(http_server):
    """N1: aclose() must not wait for an in-flight RPC (an SSE read can block
    ~5min) — it cancels the runner so shutdown stays prompt."""
    import contextlib

    import anyio

    from tollbooth.upstream import HttpUpstream

    upstream = HttpUpstream("remote", _http_config(http_server.url))
    await upstream.start()
    async with anyio.create_task_group() as tg:

        async def slow_call():
            with contextlib.suppress(UpstreamError):
                await upstream.call_tool("slow", {"seconds": 30})

        tg.start_soon(slow_call)
        await anyio.sleep(0.3)  # let the call get in flight
        with anyio.fail_after(5):  # would be ~30s if aclose waited for the call
            await upstream.aclose()


def test_build_upstream_dispatches_on_type(http_server):
    """N1: the factory picks the transport matching the config type."""
    from tollbooth.config import StdioUpstreamConfig
    from tollbooth.upstream import HttpUpstream, StdioUpstream, build_upstream

    stdio = build_upstream("fs", StdioUpstreamConfig(command="x"))
    http = build_upstream("remote", _http_config(http_server.url))
    assert isinstance(stdio, StdioUpstream)
    assert isinstance(http, HttpUpstream)
