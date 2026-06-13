"""Upstream MCP server transports.

`UpstreamTransport` is the interface seam: stdio is the only v1 implementation;
streamable HTTP (N1) drops in here without touching the proxy/policy core.
"""

import logging
import os
from contextlib import AsyncExitStack
from typing import Protocol
from urllib.parse import urlsplit

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from tollbooth.config import (
    HttpUpstreamConfig,
    StdioUpstreamConfig,
    UpstreamConfig,
    expand_env_refs,
)

log = logging.getLogger(__name__)

DEFAULT_INIT_TIMEOUT = 30.0


def _url_origin(url: str) -> str:
    """`scheme://host[:port]` — strips userinfo, path, and query.

    Errors and logs must echo only this: a URL may carry credentials in its
    userinfo or query string (Pattern 11). Falls back to a constant if the URL
    can't be parsed, never echoing the raw value.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        origin = f"{parts.scheme}://{host}"
        if parts.port is not None:
            origin += f":{parts.port}"
        return origin or "<url>"
    except ValueError:
        return "<url>"


def _representative_error(exc: BaseException) -> BaseException:
    """Unwrap a (possibly nested) ExceptionGroup to a representative leaf,
    preferring a real error over a cancellation."""
    cancel = anyio.get_cancelled_exc_class()
    while isinstance(exc, BaseExceptionGroup):
        real = [e for e in exc.exceptions if not isinstance(e, cancel)]
        exc = (real or list(exc.exceptions))[0]
    return exc


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

    def __init__(self, name: str, config: StdioUpstreamConfig, init_timeout: float | None = None):
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
        try:
            while True:
                result = await session.list_tools(cursor=cursor)
                tools.extend(result.tools)
                cursor = result.nextCursor
                if cursor is None:
                    return tools
        except Exception as exc:
            raise self._transport_error("list_tools", exc) from exc

    async def call_tool(self, tool: str, args: dict[str, object]) -> types.CallToolResult:
        session = self._require_session()
        try:
            return await session.call_tool(tool, args)
        except Exception as exc:
            raise self._transport_error("call_tool", exc) from exc

    def _transport_error(self, op: str, exc: Exception) -> UpstreamError:
        # Raw transport exceptions must never reach the client (str(exc) is
        # forwarded by the SDK's catch-all): wrap with TYPE only.
        return UpstreamError(
            f"upstream {self.name!r} {op} failed ({type(exc).__name__})"
        )

    async def aclose(self) -> None:
        self._session = None
        if self._stack is not None:
            stack, self._stack = self._stack, None
            try:
                await stack.aclose()
            except Exception as exc:
                # Closing a dead upstream must never take the gateway down.
                log.warning("closing upstream %r raised %s", self.name, type(exc).__name__)


class HttpUpstream:
    """One upstream streamable-HTTP MCP server (N1): client session lifecycle.

    Mirrors StdioUpstream — same AsyncExitStack, same init-timeout scoping, same
    sanitized errors — over the SDK's streamable_http_client instead of a
    subprocess. start() and aclose() must run in the same task.
    """

    def __init__(self, name: str, config: HttpUpstreamConfig, init_timeout: float | None = None):
        self.name = name
        self.config = config
        self.init_timeout = init_timeout or DEFAULT_INIT_TIMEOUT
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    def _resolve_headers(self) -> dict[str, str]:
        """Expand `${VAR}` references from the environment; fail closed naming
        an unset variable (never its value, never the header value)."""
        resolved: dict[str, str] = {}
        for header, value in self.config.headers.items():
            try:
                resolved[header] = expand_env_refs(value, os.environ)
            except KeyError as exc:
                raise UpstreamError(
                    f"upstream {self.name!r}: header {header!r} references unset "
                    f"environment variable {exc.args[0]!r}"
                ) from None
        return resolved

    async def start(self) -> None:
        if self._stack is not None:
            raise UpstreamError(f"upstream {self.name!r} is already running")
        # Resolve headers before opening anything, so a missing env var fails
        # closed without leaving a transport half-open.
        headers = self._resolve_headers()
        self._stack = AsyncExitStack()
        try:
            # We own the httpx client (configured with headers), so we manage its
            # lifecycle on the stack; streamable_http_client won't when one is
            # supplied. The timeout wraps only initialize() — anyio scopes are
            # strictly nested and must not span a long-lived context's entry.
            client = create_mcp_http_client(headers=headers or None)
            await self._stack.enter_async_context(client)
            read, write, _ = await self._stack.enter_async_context(
                streamable_http_client(self.config.url, http_client=client)
            )
            self._session = await self._stack.enter_async_context(ClientSession(read, write))
            with anyio.fail_after(self.init_timeout):
                await self._session.initialize()
        except TimeoutError as exc:
            await self._teardown()
            raise UpstreamError(
                f"upstream {self.name!r} did not finish initializing within "
                f"{self.init_timeout:.0f}s ({_url_origin(self.config.url)})"
            ) from exc
        except BaseException as exc:
            # A transport-level connection failure closes the read stream, which
            # CANCELS initialize() — the real cause (e.g. ConnectError) surfaces
            # only when the transport context is torn down. Teardown to capture
            # it. Prefer a concrete error; fall back to the teardown cause for a
            # bare cancellation. If neither is concrete, this was a genuine
            # external cancel — propagate it untouched.
            cause = await self._teardown()
            root = exc if isinstance(exc, Exception) else cause
            if root is None:
                raise
            # Origin + exception TYPE only: the raw URL may carry credentials and
            # transport exceptions can echo headers/URLs (Pattern 11).
            raise UpstreamError(
                f"upstream {self.name!r} failed to start "
                f"({_url_origin(self.config.url)}): {type(root).__name__}"
            ) from root
        log.info("upstream %r started (%s)", self.name, _url_origin(self.config.url))

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        return self._session

    async def list_tools(self) -> list[types.Tool]:
        session = self._require_session()
        tools: list[types.Tool] = []
        cursor: str | None = None
        try:
            while True:
                result = await session.list_tools(cursor=cursor)
                tools.extend(result.tools)
                cursor = result.nextCursor
                if cursor is None:
                    return tools
        except Exception as exc:
            raise self._transport_error("list_tools", exc) from exc

    async def call_tool(self, tool: str, args: dict[str, object]) -> types.CallToolResult:
        session = self._require_session()
        try:
            return await session.call_tool(tool, args)
        except Exception as exc:
            raise self._transport_error("call_tool", exc) from exc

    def _transport_error(self, op: str, exc: Exception) -> UpstreamError:
        # Origin + exception TYPE only — never the raw URL or headers.
        return UpstreamError(
            f"upstream {self.name!r} {op} failed "
            f"({_url_origin(self.config.url)}: {type(exc).__name__})"
        )

    async def _teardown(self) -> BaseException | None:
        """Close the transport stack; return the representative error it raised
        (digging through ExceptionGroups), or None on a clean close."""
        self._session = None
        if self._stack is None:
            return None
        stack, self._stack = self._stack, None
        try:
            await stack.aclose()
            return None
        except BaseException as exc:  # noqa: BLE001 - cleanup must never propagate
            return _representative_error(exc)

    async def aclose(self) -> None:
        cause = await self._teardown()
        if cause is not None:
            # Closing a dead upstream must never take the gateway down.
            log.warning("closing upstream %r raised %s", self.name, type(cause).__name__)


def build_upstream(name: str, config: UpstreamConfig) -> UpstreamTransport:
    """Construct the transport matching a server config's type (N1)."""
    if isinstance(config, StdioUpstreamConfig):
        return StdioUpstream(name, config)
    if isinstance(config, HttpUpstreamConfig):
        return HttpUpstream(name, config)
    # Unreachable: config is the StdioUpstreamConfig | HttpUpstreamConfig union.
    raise UpstreamError(f"upstream {name!r}: unsupported transport config")
