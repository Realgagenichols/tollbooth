"""Tests for R1: upstream transport (stdio lifecycle, discovery, forwarding)."""

import sys

import pytest

from tollbooth.upstream import StdioUpstream, UpstreamError

pytestmark = pytest.mark.anyio


async def test_lists_tools(make_upstream_config):
    upstream = StdioUpstream("echo", make_upstream_config())
    try:
        await upstream.start()
        tools = await upstream.list_tools()
        assert {t.name for t in tools} == {"echo", "shout"}
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
