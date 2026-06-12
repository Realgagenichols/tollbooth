"""The gateway proxy: an MCP server facing the client, fanned out to upstreams.

Tool names are exposed as `{server}_{tool}` and routed via a mapping table —
never by string-splitting, since server names may contain underscores (R1).
Every call runs the request pipeline; every result runs the result pipeline.
"""

import logging
import uuid
from contextlib import AsyncExitStack

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tollbooth.pipeline import Pipeline, ToolCall
from tollbooth.policy import Decision
from tollbooth.upstream import UpstreamError, UpstreamTransport

log = logging.getLogger(__name__)


class GatewayError(Exception):
    """Gateway-level configuration/runtime failure; message is user-facing."""


class _ResultWithheld(Exception):
    """Internal: a structured-content leaf was blocked; message is user-facing."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], isError=True
    )


class Gateway:
    """Aggregating MCP proxy over N upstream transports."""

    def __init__(self, upstreams: dict[str, UpstreamTransport], pipeline: Pipeline):
        self.upstreams = upstreams
        self.pipeline = pipeline
        # namespaced tool name -> (server name, original tool name)
        self._routes: dict[str, tuple[str, str]] = {}
        self.server = self._build_server()

    # -- lifecycle ---------------------------------------------------------

    async def start_upstreams(self) -> None:
        """Start all upstreams; on any failure, close the already-started ones."""
        async with AsyncExitStack() as stack:
            for upstream in self.upstreams.values():
                await upstream.start()
                stack.push_async_callback(upstream.aclose)
            # All started — detach the callbacks so the upstreams stay running.
            # The detached stack is intentionally discarded: shutdown is owned
            # by Gateway.aclose() (StdioUpstream.aclose is idempotent).
            stack.pop_all()

    async def aclose(self) -> None:
        for upstream in self.upstreams.values():
            await upstream.aclose()

    # -- tool aggregation ---------------------------------------------------

    async def _refresh_tools(self) -> list[types.Tool]:
        """Aggregate upstream catalogs, namespace them, rebuild the route table.

        A dead upstream must not poison discovery for healthy ones: its catalog
        is skipped (loudly), and its previously-known routes drop out so calls
        to it get a clear unknown-tool/dead-upstream error instead of a hang.
        """
        tools: list[types.Tool] = []
        routes: dict[str, tuple[str, str]] = {}
        for server_name, upstream in self.upstreams.items():
            try:
                upstream_tools = await upstream.list_tools()
            except Exception as exc:
                # Exception TYPE only (input-echo lesson).
                log.error(
                    "skipping catalog of upstream %r: %s", server_name, type(exc).__name__
                )
                continue
            for tool in upstream_tools:
                namespaced = f"{server_name}_{tool.name}"
                if namespaced in routes:
                    other = routes[namespaced]
                    raise GatewayError(
                        f"tool name collision: {namespaced!r} maps to both "
                        f"{other[0]}/{other[1]} and {server_name}/{tool.name}"
                    )
                routes[namespaced] = (server_name, tool.name)
                tools.append(tool.model_copy(update={"name": namespaced}))
        self._routes = routes
        return tools

    # -- request handling ----------------------------------------------------

    async def _handle_call(self, name: str, args: dict) -> types.CallToolResult:
        if name not in self._routes:
            await self._refresh_tools()
        route = self._routes.get(name)
        if route is None:
            return _error_result(f"tollbooth: unknown tool {name!r}.")
        server_name, tool_name = route
        call = ToolCall(
            server=server_name, tool=tool_name, args=args, call_id=uuid.uuid4().hex
        )

        verdict = self.pipeline.evaluate_request(call)
        if verdict.decision is not Decision.ALLOW:
            return _error_result(verdict.message)

        try:
            result = await self.upstreams[server_name].call_tool(tool_name, args)
        except UpstreamError as exc:
            return _error_result(f"tollbooth: {exc}")
        except Exception as exc:
            # Exception TYPE only (input-echo lesson); isolate to this call.
            log.error("call to %s/%s failed: %s", server_name, tool_name, type(exc).__name__)
            return _error_result(
                f"tollbooth: call to upstream {server_name!r} failed "
                f"({type(exc).__name__})."
            )

        return self._process_result(call, result)

    def _process_result(
        self, call: ToolCall, result: types.CallToolResult
    ) -> types.CallToolResult:
        # Text blocks and structuredContent both run the result pipeline
        # (DLP redacts here, R7); any non-allow verdict withholds the result.
        processed: list[types.ContentBlock] = []
        for block in result.content:
            if isinstance(block, types.TextContent):
                verdict = self.pipeline.process_result(call, block.text)
                if verdict.decision is not Decision.ALLOW or verdict.content is None:
                    return _error_result(verdict.message)
                processed.append(block.model_copy(update={"text": verdict.content}))
            else:
                # Non-text blocks (images, EmbeddedResource) pass through
                # unscanned in v1; EmbeddedResource text lands with M3's
                # resource scanning (SPEC out-of-scope note).
                processed.append(block)
        structured = result.structuredContent
        if structured is not None:
            try:
                structured = self._scan_structured(call, structured)
            except _ResultWithheld as withheld:
                return _error_result(withheld.message)
        return result.model_copy(update={"content": processed, "structuredContent": structured})

    def _scan_structured(self, call: ToolCall, value: object) -> object:
        """Run the result pipeline over each leaf of structuredContent (R7).

        Leaves are scanned RAW, never as serialized JSON: an escaping layer
        between detector and payload (\\t -> backslash-t) defeats patterns
        written for raw text (section-3 review lesson). Non-bool numeric
        leaves are scanned via str(); one that would need redaction can't
        carry a marker, so the whole result is withheld (R4).
        """
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, str):
            verdict = self.pipeline.process_result(call, value)
            if verdict.decision is not Decision.ALLOW or verdict.content is None:
                raise _ResultWithheld(verdict.message)
            return verdict.content
        if isinstance(value, int | float):
            text = str(value)
            verdict = self.pipeline.process_result(call, text)
            if verdict.decision is not Decision.ALLOW or verdict.content is None:
                raise _ResultWithheld(verdict.message)
            if verdict.content != text:
                log.error(
                    "numeric leaf in structuredContent of %s/%s needs redaction",
                    call.server,
                    call.tool,
                )
                raise _ResultWithheld(
                    f"tollbooth: result of {call.server}/{call.tool} withheld — "
                    "sensitive data in structured content could not be redacted."
                )
            return value
        if isinstance(value, dict):
            scanned: dict = {}
            for key, item in value.items():
                if isinstance(key, str):
                    verdict = self.pipeline.process_result(call, key)
                    if verdict.decision is not Decision.ALLOW or verdict.content is None:
                        raise _ResultWithheld(verdict.message)
                    if verdict.content != key:
                        # Renaming keys would mutate the API shape — a key that
                        # needs redaction withholds the result instead (R4).
                        log.error(
                            "dict key in structuredContent of %s/%s needs redaction",
                            call.server,
                            call.tool,
                        )
                        raise _ResultWithheld(
                            f"tollbooth: result of {call.server}/{call.tool} withheld — "
                            "sensitive data in structured content could not be redacted."
                        )
                scanned[key] = self._scan_structured(call, item)
            return scanned
        if isinstance(value, list):
            return [self._scan_structured(call, v) for v in value]
        return value

    # -- MCP server ----------------------------------------------------------

    def _build_server(self) -> Server:
        server = Server("tollbooth")

        @server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return await self._refresh_tools()

        # Schema validation stays with the upstreams: the gateway is a
        # transparent security boundary, not a second validator.
        @server.call_tool(validate_input=False)
        async def handle_call_tool(name: str, args: dict) -> types.CallToolResult:
            return await self._handle_call(name, args)

        return server

    async def run_stdio(self) -> None:
        """Serve the gateway on stdio (the client-facing transport)."""
        async with stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())
