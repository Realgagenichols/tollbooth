"""Claude Code hook adapter (R15): policy + DLP for the client's own tools.

`tollbooth hook pre|post` is wired into Claude Code's PreToolUse/PostToolUse
hooks: it reads the hook event JSON from stdin, runs the SAME pipeline the
gateway uses (policy → DLP → plugins), and answers in hook JSON on stdout —
pre: deny / ask, or silence to defer to the client's native permission flow
(tollbooth never auto-approves); post: redacted output via
`updatedToolOutput`, or a withholding message when a result is blocked.

Fail-closed (R4): ANY internal error — malformed stdin, broken config,
pipeline crash — emits a blocking response naming only the exception type.
Hook stdin is external input: tool arguments and results may carry secrets,
so validation errors never echo values (Patterns 11, 13).
"""

import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO

from pydantic import BaseModel, ConfigDict, ValidationError

from tollbooth.audit import AuditLogger, audit_key_from_env
from tollbooth.config import VIRTUAL_SERVER, GatewayConfig, load_config
from tollbooth.pipeline import Pipeline, ToolCall
from tollbooth.plugins import build_interceptors
from tollbooth.policy import Decision

log = logging.getLogger(__name__)

_MCP_PREFIX = "mcp__"
_EVENT_NAMES = {"pre": "PreToolUse", "post": "PostToolUse"}


class HookInputError(Exception):
    """Malformed hook event on stdin; message is location info, never values."""


class PreToolUseEvent(BaseModel):
    """The PreToolUse fields we consume. extra="ignore": hook payloads grow
    with the client (cwd, permission_mode, ...) and new fields must not make
    a security hook reject every event."""

    model_config = ConfigDict(extra="ignore")

    session_id: str = ""
    tool_name: str
    tool_input: dict[str, Any] = {}


class PostToolUseEvent(PreToolUseEvent):
    # Shape varies by tool: string, dict, or list of content blocks.
    tool_response: Any = None


def parse_event(raw_text: str, kind: str) -> PreToolUseEvent:
    model = PostToolUseEvent if kind == "post" else PreToolUseEvent
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        # JSONDecodeError messages are coordinates only — safe to interpolate.
        raise HookInputError(f"hook stdin is not valid JSON: {exc}") from exc
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise HookInputError(f"invalid hook event: {details}") from exc


def resolve_tool(tool_name: str) -> tuple[str, str]:
    """Map a hook tool_name to (server, tool) for policy purposes.

    MCP tools arrive as `mcp__{server}__{tool}`; we split on the FIRST `__`
    after the prefix, so a server name that itself contains `__` would
    mis-attribute — a documented limitation (MCP's naming convention is
    ambiguous there). Everything else routes as the virtual `claude` server.
    """
    if tool_name.startswith(_MCP_PREFIX):
        server, sep, tool = tool_name.removeprefix(_MCP_PREFIX).partition("__")
        if sep and server and tool:
            return server, tool
    return VIRTUAL_SERVER, tool_name


def _hook_output(kind: str, fields: dict) -> dict:
    return {"hookSpecificOutput": {"hookEventName": _EVENT_NAMES[kind], **fields}}


def handle_pre(event: PreToolUseEvent, pipeline: Pipeline) -> dict | None:
    """Request path. Returns the hook JSON, or None to defer: an ALLOW from
    tollbooth must not auto-approve a call the user expects the client's own
    permission system to prompt for."""
    server, tool = resolve_tool(event.tool_name)
    call = ToolCall(server=server, tool=tool, args=event.tool_input, call_id=uuid.uuid4().hex)
    result = pipeline.evaluate_request(call)
    if result.decision is Decision.ALLOW:
        return None
    if result.decision is Decision.DENY:
        decision = "deny"
    elif result.decision is Decision.REQUIRE_APPROVAL:
        decision = "ask"
    else:
        # Exhaustive over the Decision enum: an unmapped member must fail
        # (and be caught by the fail-closed wrapper), never silently defer.
        raise ValueError(f"unmapped decision {result.decision!r}")
    return _hook_output(
        kind="pre",
        fields={"permissionDecision": decision, "permissionDecisionReason": result.message},
    )


class _Withheld(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _map_string_leaves(node: Any, transform) -> Any:
    """Apply transform to every string leaf, preserving structure (and dict
    keys — keys are schema). Scans the RAW string representation the DLP
    patterns were written for, never a serialized blob (Pattern 12)."""
    if isinstance(node, str):
        return transform(node)
    if isinstance(node, list):
        return [_map_string_leaves(item, transform) for item in node]
    if isinstance(node, dict):
        return {key: _map_string_leaves(value, transform) for key, value in node.items()}
    return node


def handle_post(event: PostToolUseEvent, pipeline: Pipeline) -> dict | None:
    """Result path. Redactions come back via updatedToolOutput; a blocked
    result replaces the output entirely with the withholding message."""
    server, tool = resolve_tool(event.tool_name)
    call = ToolCall(server=server, tool=tool, args=event.tool_input, call_id=uuid.uuid4().hex)
    changed = False

    def scan(text: str) -> str:
        nonlocal changed
        verdict = pipeline.process_result(call, text)
        if verdict.decision is not Decision.ALLOW:
            raise _Withheld(verdict.message)
        if verdict.content != text:
            changed = True
        return verdict.content

    try:
        updated = _map_string_leaves(event.tool_response, scan)
    except _Withheld as withheld:
        return _hook_output(kind="post", fields={"updatedToolOutput": withheld.message})
    if not changed:
        return None
    return _hook_output(kind="post", fields={"updatedToolOutput": updated})


def _fail_closed_output(kind: str, exc: Exception) -> dict:
    # Exception TYPE only: arbitrary errors may echo stdin values (Pattern 11).
    reason = f"tollbooth: hook failed closed ({type(exc).__name__})"
    if kind == "post":
        return _hook_output(kind, {"updatedToolOutput": f"{reason} — result withheld"})
    return _hook_output(
        kind, {"permissionDecision": "deny", "permissionDecisionReason": reason}
    )


def _build_pipeline(config: GatewayConfig, event: PreToolUseEvent, stack) -> Pipeline:
    request_interceptors, result_interceptors = build_interceptors(config)
    if config.audit.log is not None:
        stream: TextIO = stack.enter_context(
            open(config.audit.log, "a", encoding="utf-8")  # noqa: SIM115
        )
        path: str | None = config.audit.log
    else:
        stream, path = sys.stderr, None
    audit = AuditLogger(
        stream,
        key=audit_key_from_env(),
        record=config.audit.record,
        # Correlate to the client's session; file-aware path mode keeps the
        # chain intact across concurrent hook processes and a live gateway.
        session_id=event.session_id or None,
        path=path,
    )
    return Pipeline(
        request_interceptors=request_interceptors,
        result_interceptors=result_interceptors,
        fail_open=(config.policy.failure_mode == "open"),
        audit=audit,
    )


def run_hook(kind: str, config_path: str, stdin: TextIO, stdout: TextIO) -> int:
    """Process one hook invocation end to end. Always exits 0: the verdict is
    the JSON on stdout, and an internal failure IS a blocking verdict."""
    from contextlib import ExitStack

    if kind not in _EVENT_NAMES:
        raise ValueError(f"unknown hook kind {kind!r}")  # CLI bug, not input
    try:
        config = load_config(Path(config_path))
        event = parse_event(stdin.read(), kind)
        with ExitStack() as stack:
            pipeline = _build_pipeline(config, event, stack)
            handler = handle_pre if kind == "pre" else handle_post
            output = handler(event, pipeline)
    except Exception as exc:
        log.error("hook %s failed closed: %s", kind, type(exc).__name__)
        output = _fail_closed_output(kind, exc)
    if output is not None:
        json.dump(output, stdout)
        stdout.write("\n")
    return 0
