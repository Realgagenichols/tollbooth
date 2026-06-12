"""Tests for R1/R2/R5 proxy scenarios: aggregation, routing, isolation, enforcement."""

import anyio
import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from tollbooth.pipeline import Pipeline, PolicyInterceptor
from tollbooth.policy import Decision, Rule
from tollbooth.proxy import Gateway
from tollbooth.upstream import UpstreamError

pytestmark = pytest.mark.anyio


class FakeUpstream:
    """In-process UpstreamTransport double; records forwarded calls."""

    def __init__(self, name, tools, dead=False):
        self.name = name
        self.tools = tools  # dict tool_name -> callable(args) -> str
        self.dead = dead
        self.calls = []

    async def start(self):
        pass

    async def list_tools(self):
        return [
            types.Tool(name=tool, inputSchema={"type": "object", "additionalProperties": True})
            for tool in self.tools
        ]

    async def call_tool(self, tool, args):
        if self.dead:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        self.calls.append((tool, args))
        text = self.tools[tool](args)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)], isError=False
        )

    async def aclose(self):
        pass


def make_gateway(upstreams, rules=None, default=Decision.ALLOW):
    pipeline = Pipeline(
        request_interceptors=[PolicyInterceptor(rules=rules or [], default=default)]
    )
    return Gateway(upstreams={u.name: u for u in upstreams}, pipeline=pipeline)


def fs_upstream(**kwargs):
    return FakeUpstream(
        "fs",
        {
            "read_file": lambda args: f"contents of {args['path']}",
            "write_file": lambda args: "ok",
        },
        **kwargs,
    )


def github_upstream():
    return FakeUpstream("github", {"create_issue": lambda args: "issue #1"})


# R1 scenario: pass-through of an allowed tool call
async def test_allowed_call_passes_through_unchanged():
    fs = fs_upstream()
    gateway = make_gateway([fs])
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("fs_read_file", {"path": "/tmp/x"})
    assert result.isError is False
    assert result.content[0].text == "contents of /tmp/x"
    assert fs.calls == [("read_file", {"path": "/tmp/x"})]  # original tool name upstream


# R1 scenario: tool discovery is aggregated and namespaced
async def test_discovery_aggregates_and_namespaces():
    gateway = make_gateway([fs_upstream(), github_upstream()])
    async with create_connected_server_and_client_session(gateway.server) as client:
        listed = await client.list_tools()
    assert {t.name for t in listed.tools} == {
        "fs_read_file",
        "fs_write_file",
        "github_create_issue",
    }


# R1 scenario: underscore in server name routes correctly
async def test_underscore_server_name_routes_via_mapping_table():
    my_api = FakeUpstream("my_api", {"get_user": lambda args: "user-42"})
    gateway = make_gateway([my_api])
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("my_api_get_user", {})
    assert result.isError is False
    assert my_api.calls == [("get_user", {})]


# R1 scenario: upstream dies mid-session — isolated, others keep working
async def test_dead_upstream_isolated():
    fs = fs_upstream(dead=True)
    github = github_upstream()
    gateway = make_gateway([fs, github])
    async with create_connected_server_and_client_session(gateway.server) as client:
        dead = await client.call_tool("fs_read_file", {"path": "/tmp/x"})
        alive = await client.call_tool("github_create_issue", {"title": "t"})
    assert dead.isError is True
    assert "fs" in dead.content[0].text
    assert alive.isError is False


# R2 scenario: deny by tool name — upstream never contacted
async def test_denied_call_never_reaches_upstream():
    fs = fs_upstream()
    rules = [Rule(name="no-writes", action=Decision.DENY, server="fs", tool="write_file")]
    gateway = make_gateway([fs], rules=rules)
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("fs_write_file", {"path": "/tmp/x"})
    assert result.isError is True
    assert "no-writes" in result.content[0].text
    assert fs.calls == []  # never forwarded


# R5 scenario: approvable message distinct from deny
async def test_approval_blocked_with_approvable_message():
    fs = fs_upstream()
    rules = [
        Rule(name="ask-first", action=Decision.REQUIRE_APPROVAL, server="fs", tool="write_file")
    ]
    gateway = make_gateway([fs], rules=rules)
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("fs_write_file", {"path": "/tmp/x"})
    assert result.isError is True
    text = result.content[0].text
    assert "approval" in text.lower()
    assert "ask-first" in text
    assert fs.calls == []


async def test_unknown_tool_returns_clear_error():
    gateway = make_gateway([fs_upstream()])
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("fs_no_such_tool", {})
    assert result.isError is True
    assert "unknown tool" in result.content[0].text.lower()


async def test_namespaced_name_collision_is_clear_error():
    """server 'a' tool 'b_c' vs server 'a_b' tool 'c' — same namespaced name.

    GatewayError raised server-side; the SDK surfaces it to the client as an
    McpError carrying the collision message.
    """
    from mcp.shared.exceptions import McpError

    a = FakeUpstream("a", {"b_c": lambda args: "x"})
    a_b = FakeUpstream("a_b", {"c": lambda args: "y"})
    gateway = make_gateway([a, a_b])
    async with create_connected_server_and_client_session(gateway.server) as client:
        with pytest.raises(McpError, match="collision"):
            await client.list_tools()


@pytest.mark.regression
async def test_dead_upstream_does_not_poison_discovery():
    """One upstream failing list_tools must not break the others' catalogs."""

    class DeadCatalog(FakeUpstream):
        async def list_tools(self):
            raise UpstreamError("upstream 'fs' list_tools failed (ClosedResourceError)")

    fs = DeadCatalog("fs", {})
    github = github_upstream()
    gateway = make_gateway([fs, github])
    async with create_connected_server_and_client_session(gateway.server) as client:
        listed = await client.list_tools()
        alive = await client.call_tool("github_create_issue", {"title": "t"})
    assert {t.name for t in listed.tools} == {"github_create_issue"}
    assert alive.isError is False


async def test_start_upstreams_rollback_on_partial_failure():
    """If the 2nd upstream fails to start, the 1st is closed, the 3rd never starts."""

    class TrackedUpstream(FakeUpstream):
        def __init__(self, name, fail=False):
            super().__init__(name, {})
            self.fail = fail
            self.started = False
            self.closed = False

        async def start(self):
            if self.fail:
                raise UpstreamError(f"upstream {self.name!r} failed to start")
            self.started = True

        async def aclose(self):
            self.closed = True

    first = TrackedUpstream("a")
    second = TrackedUpstream("b", fail=True)
    third = TrackedUpstream("c")
    gateway = make_gateway([first, second, third])
    with pytest.raises(UpstreamError, match="'b'"):
        await gateway.start_upstreams()
    assert first.started and first.closed  # rolled back
    assert third.started is False  # never reached


# Pattern 8: concurrent calls through one gateway map to the right responses
async def test_concurrent_calls_no_cross_talk():
    echo = FakeUpstream("echo", {"echo": lambda args: f"reply-{args['n']}"})
    gateway = make_gateway([echo])
    results: dict[int, str] = {}

    async with create_connected_server_and_client_session(gateway.server) as client:

        async def one_call(n):
            result = await client.call_tool("echo_echo", {"n": n})
            results[n] = result.content[0].text

        async with anyio.create_task_group() as tg:
            for n in range(20):
                tg.start_soon(one_call, n)

    assert results == {n: f"reply-{n}" for n in range(20)}


class StructuredFake:
    """Upstream double returning structuredContent alongside empty content."""

    def __init__(self, structured):
        self.name = "api"
        self.structured = structured

    async def start(self):
        pass

    async def list_tools(self):
        return [
            types.Tool(name="fetch", inputSchema={"type": "object", "additionalProperties": True})
        ]

    async def call_tool(self, tool, args):
        return types.CallToolResult(content=[], structuredContent=self.structured, isError=False)

    async def aclose(self):
        pass


def make_dlp_gateway(upstream):
    from tollbooth.dlp import DlpResultInterceptor

    pipeline = Pipeline(
        request_interceptors=[PolicyInterceptor(rules=[], default=Decision.ALLOW)],
        result_interceptors=[DlpResultInterceptor()],
    )
    return Gateway(upstreams={upstream.name: upstream}, pipeline=pipeline)


class TestStructuredContent:
    # R7: structuredContent gets its own scanning pass
    async def test_secret_in_structured_content_redacted(self):
        fake = StructuredFake({"note": "key AKIAIOSFODNN7EXAMPLE", "ok": True})
        gateway = make_dlp_gateway(fake)
        async with create_connected_server_and_client_session(gateway.server) as client:
            result = await client.call_tool("api_fetch", {})
        assert result.isError is False
        assert result.structuredContent["note"] == "key [REDACTED:aws-access-key]"
        assert result.structuredContent["ok"] is True

    # R4: redaction that breaks the JSON (bare-number PAN) blocks the result
    async def test_unredactable_structured_content_blocked(self):
        fake = StructuredFake({"card": 4111111111111111})
        gateway = make_dlp_gateway(fake)
        async with create_connected_server_and_client_session(gateway.server) as client:
            result = await client.call_tool("api_fetch", {})
        assert result.isError is True
        message = result.content[0].text
        assert "withheld" in message
        assert "4111111111111111" not in message

    async def test_clean_structured_content_untouched(self):
        fake = StructuredFake({"items": [1, 2, 3], "status": "fine"})
        gateway = make_dlp_gateway(fake)
        async with create_connected_server_and_client_session(gateway.server) as client:
            result = await client.call_tool("api_fetch", {})
        assert result.isError is False
        assert result.structuredContent == {"items": [1, 2, 3], "status": "fine"}
