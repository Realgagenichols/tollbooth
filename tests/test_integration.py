"""End-to-end tests: full config through gateway to upstreams (R1–R5, S1).

Two levels:
- in-memory: real config YAML -> build_gateway -> fake upstreams, audit asserted
- subprocess: the installed `tollbooth run` proxying the echo server over real
  stdio, driven by a real MCP client session (acceptance-grade)
"""

import io
import json
import sys

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from tests.conftest import ECHO_SERVER
from tests.test_proxy import FakeUpstream, fs_upstream, github_upstream
from tollbooth.audit import AuditLogger
from tollbooth.config import load_config
from tollbooth.main import build_gateway
from tollbooth.proxy import Gateway

pytestmark = pytest.mark.anyio

FULL_CONFIG = """
servers:
  fs:
    command: unused-here
  github:
    command: unused-here
policy:
  default: allow
  failure_mode: closed
  rules:
    - name: writes-stay-in-project
      action: deny
      server: fs
      tool: write_file
      where:
        path:
          not_prefix: /project
    - name: issues-need-approval
      action: require-approval
      server: github
      tool: create_issue
"""


async def test_full_stack_policy_and_audit(tmp_path):
    """R1+R2+R4+R5+S1: allowed forwards, denied short-circuits, approval distinct,
    every decision audited without values."""
    config_path = tmp_path / "tollbooth.yaml"
    config_path.write_text(FULL_CONFIG, encoding="utf-8")
    config = load_config(config_path)

    audit_stream = io.StringIO()
    gateway = build_gateway(config, audit_stream=audit_stream)
    # Swap the configured StdioUpstreams for in-process fakes (same names).
    fs, github = fs_upstream(), github_upstream()
    gateway.upstreams = {"fs": fs, "github": github}

    async with create_connected_server_and_client_session(gateway.server) as client:
        allowed = await client.call_tool("fs_read_file", {"path": "/project/a.txt"})
        denied = await client.call_tool("fs_write_file", {"path": "/etc/passwd"})
        approval = await client.call_tool("github_create_issue", {"title": "secret-title"})

    # Allowed: forwarded, result intact
    assert allowed.isError is False
    assert allowed.content[0].text == "contents of /project/a.txt"
    # Denied: upstream untouched, rule named
    assert denied.isError is True
    assert "writes-stay-in-project" in denied.content[0].text
    assert all(tool != "write_file" for tool, _ in fs.calls)
    # Approval: distinct wording, upstream untouched
    assert approval.isError is True
    assert "approval" in approval.content[0].text.lower()
    assert github.calls == []

    # S1: one audit event per decision, no argument values anywhere
    events = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [e["decision"] for e in events] == ["allow", "deny", "require-approval"]
    assert events[1]["reason_id"] == "writes-stay-in-project"
    assert "secret-title" not in audit_stream.getvalue()
    assert "/etc/passwd" not in audit_stream.getvalue()


async def test_fail_closed_full_stack(tmp_path):
    """R4: a crashing interceptor inside the full gateway denies the call."""

    class Boom:
        name = "boom"

        def check_request(self, call):
            raise RuntimeError("kaput")

    from tollbooth.pipeline import Pipeline

    audit_stream = io.StringIO()
    gateway = Gateway(
        upstreams={"fs": fs_upstream()},
        pipeline=Pipeline(request_interceptors=[Boom()], audit=AuditLogger(audit_stream)),
    )
    async with create_connected_server_and_client_session(gateway.server) as client:
        result = await client.call_tool("fs_read_file", {"path": "/x"})
    assert result.isError is True
    assert "fail-closed" in result.content[0].text
    [event] = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert event["reason_id"] == "interceptor-failure:boom"


async def test_subprocess_gateway_end_to_end(tmp_path):
    """Acceptance: real `tollbooth run` subprocess proxying the echo server
    over actual stdio — allowed call succeeds, denied call blocked."""
    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "tollbooth.yaml"
    config_path.write_text(
        f"""
servers:
  echo:
    command: {sys.executable}
    args: ["{ECHO_SERVER}"]
policy:
  default: allow
  rules:
    - name: no-shouting
      action: deny
      server: echo
      tool: shout
audit_log: {audit_path}
""",
        encoding="utf-8",
    )

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tollbooth.main", "run", "-c", str(config_path)],
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        listed = await session.list_tools()
        assert {t.name for t in listed.tools} == {"echo_echo", "echo_shout", "echo_leak"}

        allowed = await session.call_tool("echo_echo", {"text": "hi"})
        assert allowed.isError is False
        assert allowed.content[0].text == "echo: hi"

        denied = await session.call_tool("echo_shout", {"text": "hi"})
        assert denied.isError is True
        assert "no-shouting" in denied.content[0].text

        # M2 acceptance: secret-bearing result arrives redacted over real stdio
        leaked = await session.call_tool("echo_leak", {})
        assert leaked.isError is False
        assert "AKIAIOSFODNN7EXAMPLE" not in leaked.content[0].text
        assert "[REDACTED:aws-access-key]" in leaked.content[0].text

        # M2 acceptance: PAN in request args blocked before reaching upstream
        blocked = await session.call_tool("echo_echo", {"text": "card 4111111111111111"})
        assert blocked.isError is True
        assert "pan" in blocked.content[0].text
        assert "4111111111111111" not in blocked.content[0].text

    audit_text = audit_path.read_text()
    events = [json.loads(line) for line in audit_text.splitlines()]
    # M3 (R9): the run opens with a session-start event carrying a config
    # digest, never config contents.
    start, *decisions = events
    assert start["event"] == "session-start"
    assert len(start["config_digest"]) == 64
    # leak emits TWO redaction events: FastMCP returns the secret in both the
    # text block and structuredContent, and each surface is scanned (R7).
    assert [e["decision"] for e in decisions] == [
        "allow", "deny", "allow", "allow", "allow", "deny",
    ]
    assert decisions[3]["reason_id"] == "redacted:aws-access-key"
    assert decisions[4]["reason_id"] == "redacted:aws-access-key"
    assert decisions[5]["reason_id"] == "dlp:pan"
    # R9: one session, every event stamped with it; request/result of the
    # leak call share one call id.
    assert len({e["session"] for e in events}) == 1
    assert decisions[2]["call_id"] == decisions[3]["call_id"]
    assert "4111111111111111" not in audit_text
    assert "AKIAIOSFODNN7EXAMPLE" not in audit_text


DLP_CONFIG = """
servers:
  fs:
    command: unused-here
policy:
  default: allow
"""


async def test_full_stack_dlp_redaction_and_blocking(tmp_path):
    """R6+R7+S1 in-memory full stack: result redacted, request blocked,
    both audited by pattern id without values."""
    config_path = tmp_path / "tollbooth.yaml"
    config_path.write_text(DLP_CONFIG, encoding="utf-8")
    audit_stream = io.StringIO()
    gateway = build_gateway(load_config(config_path), audit_stream=audit_stream)
    fs = FakeUpstream(
        "fs", {"read_file": lambda args: f"aws_key=AKIAIOSFODNN7EXAMPLE in {args['path']}"}
    )
    gateway.upstreams = {"fs": fs}

    async with create_connected_server_and_client_session(gateway.server) as client:
        redacted = await client.call_tool("fs_read_file", {"path": "/app/.env"})
        blocked = await client.call_tool(
            "fs_read_file", {"path": "/notes/card-4111111111111111.txt"}
        )

    assert redacted.isError is False
    assert redacted.content[0].text == "aws_key=[REDACTED:aws-access-key] in /app/.env"
    assert blocked.isError is True
    assert "pan" in blocked.content[0].text
    # The blocked call never reached the upstream (egress stopped at the gate).
    assert len(fs.calls) == 1

    audit_text = audit_stream.getvalue()
    assert "AKIAIOSFODNN7EXAMPLE" not in audit_text
    assert "4111111111111111" not in audit_text
    events = [json.loads(line) for line in audit_text.splitlines()]
    assert events[1]["reason_id"] == "redacted:aws-access-key"
    assert events[2]["reason_id"] == "dlp:pan"


async def test_concurrent_calls_no_redaction_bleed(tmp_path):
    """Cross-cutting Pattern 8: 20 concurrent DLP-scanned calls through one
    gateway — every response redacts its own content, no cross-call mixups."""
    import anyio

    config_path = tmp_path / "tollbooth.yaml"
    config_path.write_text(DLP_CONFIG, encoding="utf-8")
    gateway = build_gateway(load_config(config_path), audit_stream=io.StringIO())
    gateway.upstreams = {
        "fs": FakeUpstream(
            "fs",
            {
                "read_file": lambda args: (
                    f"file {args['n']}: ssn 123-45-6789"
                    if args["secret"]
                    else f"file {args['n']}: clean"
                )
            },
        )
    }

    results: dict[int, str] = {}
    async with create_connected_server_and_client_session(gateway.server) as client:

        async def call(n: int):
            result = await client.call_tool("fs_read_file", {"n": n, "secret": n % 2 == 0})
            results[n] = result.content[0].text

        async with anyio.create_task_group() as tg:
            for n in range(20):
                tg.start_soon(call, n)

    for n in range(20):
        expected = f"file {n}: ssn [REDACTED:ssn]" if n % 2 == 0 else f"file {n}: clean"
        assert results[n] == expected
