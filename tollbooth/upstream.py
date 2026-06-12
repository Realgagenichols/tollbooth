"""Upstream MCP server transports.

`UpstreamTransport` is the interface seam: stdio is the only v1 implementation;
streamable HTTP (N1) drops in here without touching the proxy/policy core.
"""

import logging
from contextlib import AsyncExitStack
from typing import Protocol

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

from tollbooth.config import UpstreamConfig

log = logging.getLogger(__name__)

DEFAULT_INIT_TIMEOUT = 30.0


class UpstreamError(Exception):
    """An upstream server failed to start or is unusable; message is user-facing."""


class UpstreamTransport(Protocol):
    name: str

    async def start(self) -> None: ...

    async def list_tools(self) -> list[types.Tool]: ...

    async def call_tool(self, tool: str, args: dict[str, object]) -> types.CallToolResult: ...

    async def aclose(self) -> None: ...


class StdioUpstream:
    """One upstream stdio MCP server: subprocess lifecycle + client session.

    start() and aclose() must run in the same task (the mcp SDK's stdio
    transport uses task-scoped cancel scopes).
    """

    def __init__(self, name: str, config: UpstreamConfig, init_timeout: float | None = None):
        self.name = name
        self.config = config
        self.init_timeout = init_timeout or DEFAULT_INIT_TIMEOUT
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def start(self) -> None:
        params = StdioServerParameters(
            command=self.config.command,
            args=self.config.args,
            # Merge onto the SDK's safe default environment (PATH etc.) so
            # configs only declare what's specific to the server.
            env={**get_default_environment(), **self.config.env},
        )
        if self._stack is not None:
            raise UpstreamError(f"upstream {self.name!r} is already running")
        self._stack = AsyncExitStack()
        try:
            # NOTE: the context managers must NOT be entered inside a cancel
            # scope they outlive (anyio scopes are strictly nested), so the
            # timeout wraps only the initialize() await.
            read, write = await self._stack.enter_async_context(stdio_client(params))
            self._session = await self._stack.enter_async_context(ClientSession(read, write))
            with anyio.fail_after(self.init_timeout):
                await self._session.initialize()
        except TimeoutError as exc:
            await self.aclose()
            raise UpstreamError(
                f"upstream {self.name!r} did not finish initializing within "
                f"{self.init_timeout:.0f}s (command: {self.config.command})"
            ) from exc
        except Exception as exc:
            await self.aclose()
            # Exception TYPE only: subprocess errors can echo command lines,
            # which may carry sensitive args (lessons: input-echo leaks).
            raise UpstreamError(
                f"upstream {self.name!r} failed to start "
                f"(command: {self.config.command}): {type(exc).__name__}"
            ) from exc
        log.info("upstream %r started (command: %s)", self.name, self.config.command)

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        return self._session

    async def list_tools(self) -> list[types.Tool]:
        # Follow pagination: R1 promises the UNION of upstream tools.
        session = self._require_session()
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            result = await session.list_tools(cursor=cursor)
            tools.extend(result.tools)
            cursor = result.nextCursor
            if cursor is None:
                return tools

    async def call_tool(self, tool: str, args: dict[str, object]) -> types.CallToolResult:
        return await self._require_session().call_tool(tool, args)

    async def aclose(self) -> None:
        self._session = None
        if self._stack is not None:
            stack, self._stack = self._stack, None
            try:
                await stack.aclose()
            except Exception as exc:
                # Closing a dead upstream must never take the gateway down.
                log.warning("closing upstream %r raised %s", self.name, type(exc).__name__)
