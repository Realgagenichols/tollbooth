"""Upstream MCP server transports.

`UpstreamTransport` is the interface seam: stdio is the only v1 implementation;
streamable HTTP (N1) drops in here without touching the proxy/policy core.
"""

import logging
import os
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import anyio
import mcp.types as types
from anyio.streams.memory import MemoryObjectSendStream
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
from tollbooth.oauth import FailClosedReauth, TokenStorageError, build_oauth_provider

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
        if ":" in host:  # IPv6 literal — re-bracket so host:port stays parseable
            host = f"[{host}]"
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


@dataclass
class _Call:
    """One RPC handed to the runner task; the reply (ok, payload) comes back on
    `reply`. ok=False with payload=None means the transport died."""

    method: str  # "list_tools" | "call_tool"
    tool: str | None
    args: dict[str, object] | None
    reply: MemoryObjectSendStream


class HttpUpstream:
    """One upstream streamable-HTTP MCP server (N1).

    The transport (httpx client + streamable_http_client + ClientSession) is
    owned ENTIRELY BY A DEDICATED RUNNER TASK, never the caller's task. The SDK
    runs HTTP I/O in a background task group; a connection failure cancels that
    group's scope. Were that scope in the gateway's main task (as a plain
    AsyncExitStack would put it), a dead upstream would cancel run_stdio and
    crash the WHOLE gateway. Confining it to the runner — which catches every
    failure and never lets it escape — isolates a dead upstream (R1/R4): its
    calls error cleanly while other upstreams keep working.

    list_tools/call_tool forward a `_Call` over a rendezvous channel to the
    runner and await its reply; the runner serves calls sequentially (one
    transport, one call at a time). start()/aclose() run in the same task — they
    enter/exit the task group that owns the runner.
    """

    def __init__(self, name: str, config: HttpUpstreamConfig, init_timeout: float | None = None):
        self.name = name
        self.config = config
        self.init_timeout = init_timeout or DEFAULT_INIT_TIMEOUT
        self._stack: AsyncExitStack | None = None
        self._tg: anyio.abc.TaskGroup | None = None
        self._req_send: MemoryObjectSendStream | None = None
        self._ready = anyio.Event()
        self._init_error: BaseException | None = None
        self._closed = False

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
        # Resolve headers before spawning anything, so a missing env var fails
        # closed without leaving a runner half-open.
        headers = self._resolve_headers()
        req_send, req_recv = anyio.create_memory_object_stream[_Call](0)
        self._req_send = req_send
        self._stack = AsyncExitStack()
        try:
            # The runner is a child of THIS task group (scope in our task). The
            # runner catches everything, so its failures never cancel us.
            self._tg = await self._stack.enter_async_context(anyio.create_task_group())
            self._tg.start_soon(self._run, req_recv, headers)
            # The runner sets _ready on success or failure; initialize() (the
            # first byte on the wire) is fail_after-wrapped, so a hung connect
            # can't outlast init_timeout. The +5 is a pure backstop.
            with anyio.fail_after(self.init_timeout + 5):
                await self._ready.wait()
        except TimeoutError as exc:
            await self._shutdown()
            raise UpstreamError(
                f"upstream {self.name!r} did not finish initializing within "
                f"{self.init_timeout:.0f}s ({_url_origin(self.config.url)})"
            ) from exc
        except BaseException:
            await self._shutdown()
            raise
        if self._init_error is not None:
            origin = _url_origin(self.config.url)
            err = self._init_error
            await self._shutdown()
            if isinstance(err, TimeoutError):
                raise UpstreamError(
                    f"upstream {self.name!r} did not finish initializing within "
                    f"{self.init_timeout:.0f}s ({origin})"
                ) from err
            if isinstance(err, FailClosedReauth):
                raise self._reauth_error() from err
            if isinstance(err, TokenStorageError):
                # TokenStorageError messages are already sanitized (path/reason,
                # never contents), so they're safe to surface verbatim.
                raise UpstreamError(
                    f"upstream {self.name!r} OAuth store unusable ({origin}): {err}"
                ) from err
            # Origin + exception TYPE only: the raw URL may carry credentials and
            # transport exceptions can echo headers/URLs (Pattern 11).
            raise UpstreamError(
                f"upstream {self.name!r} failed to start ({origin}): {type(err).__name__}"
            ) from err
        log.info("upstream %r started (%s)", self.name, _url_origin(self.config.url))

    async def _run(self, requests, headers: dict[str, str]) -> None:
        """Owns the transport for the upstream's lifetime; serves calls until the
        request channel closes. Catches EVERYTHING — a transport failure here
        must never reach the parent task group in the gateway's main task."""
        try:
            # `requests` is the outermost context so req_recv is always closed,
            # even on an init-failure exit before the serve loop.
            async with requests, AsyncExitStack() as stack:
                # OAuth (N2): attach the SDK provider as the httpx auth. It drives
                # auth-code+PKCE/refresh; in run mode its handlers fail closed, so
                # a missing/unrefreshable token raises FailClosedReauth (below)
                # instead of opening a browser.
                auth = None
                if self.config.auth is not None:
                    auth = build_oauth_provider(
                        self.name, self.config.url, self.config.auth, interactive=False
                    )
                # We own the httpx client (configured with headers), so we manage
                # its lifecycle here; streamable_http_client won't when supplied.
                client = create_mcp_http_client(headers=headers or None, auth=auth)
                await stack.enter_async_context(client)
                read, write, _ = await stack.enter_async_context(
                    streamable_http_client(self.config.url, http_client=client)
                )
                session = await stack.enter_async_context(ClientSession(read, write))
                # Timeout wraps only initialize() — anyio scopes are strictly
                # nested and must not span the long-lived context entries.
                with anyio.fail_after(self.init_timeout):
                    await session.initialize()
                self._ready.set()
                async for call in requests:
                    await self._serve(session, call)
        except BaseException as exc:  # noqa: BLE001 - must not escape this task
            if not self._ready.is_set():
                # Failed before signalling start(): record the cause for start().
                self._init_error = _representative_error(exc)
                self._ready.set()
            # else: started fine then died — in-flight call already got a reply
            # (below); future calls fast-fail on the closed channel.
        finally:
            self._closed = True

    async def _serve(self, session: ClientSession, call: _Call) -> None:
        try:
            if call.method == "list_tools":
                payload: object = await self._paginate(session)
            else:
                payload = await session.call_tool(call.tool, call.args or {})
        except anyio.get_cancelled_exc_class():
            # Transport died (or shutdown): unblock the caller with a transport
            # sentinel, then re-raise so the runner tears the transport down.
            await self._reply(call, False, None)
            raise
        except Exception as exc:  # a normal per-call failure — keep serving
            await self._reply(call, False, exc)
            return
        await self._reply(call, True, payload)

    async def _paginate(self, session: ClientSession) -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            result = await session.list_tools(cursor=cursor)
            tools.extend(result.tools)
            cursor = result.nextCursor
            if cursor is None:
                return tools

    async def _reply(self, call: _Call, ok: bool, payload: object) -> None:
        # Shield so a caller still gets its reply even while the runner is being
        # cancelled by a transport death.
        with anyio.CancelScope(shield=True):
            with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                async with call.reply:
                    await call.reply.send((ok, payload))

    async def _invoke(
        self, method: str, tool: str | None = None, args: dict[str, object] | None = None
    ) -> object:
        if self._req_send is None or self._closed:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        reply_send, reply_recv = anyio.create_memory_object_stream[tuple[bool, object]](1)
        try:
            await self._req_send.send(_Call(method, tool, args, reply_send))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            # The runner never received the call, so it won't close reply_send.
            reply_send.close()
            reply_recv.close()
            raise UpstreamError(f"upstream {self.name!r} is not running") from None
        async with reply_recv:
            ok, payload = await reply_recv.receive()
        if ok:
            return payload
        if payload is None:  # transport-death sentinel
            raise UpstreamError(
                f"upstream {self.name!r} {method} failed "
                f"({_url_origin(self.config.url)}: transport closed)"
            )
        if isinstance(payload, FailClosedReauth):
            # A token valid at startup expired mid-session and couldn't refresh.
            raise self._reauth_error() from payload
        raise self._transport_error(method, payload) from payload  # type: ignore[arg-type]

    def _reauth_error(self) -> UpstreamError:
        """Clean fail-closed error for an OAuth upstream needing re-auth — origin
        only, with the recovery command, never any token detail (N2)."""
        return UpstreamError(
            f"upstream {self.name!r} requires OAuth authentication "
            f"({_url_origin(self.config.url)}); run `tollbooth auth login {self.name}`"
        )

    async def list_tools(self) -> list[types.Tool]:
        return await self._invoke("list_tools")  # type: ignore[return-value]

    async def call_tool(self, tool: str, args: dict[str, object]) -> types.CallToolResult:
        return await self._invoke("call_tool", tool, args)  # type: ignore[return-value]

    def _transport_error(self, op: str, exc: BaseException) -> UpstreamError:
        # Origin + exception TYPE only — never the raw URL or headers.
        return UpstreamError(
            f"upstream {self.name!r} {op} failed "
            f"({_url_origin(self.config.url)}: {type(exc).__name__})"
        )

    async def _shutdown(self) -> None:
        """Stop the runner and close the transport; never propagates a
        non-cancellation exception (a cancel of our own task still propagates)."""
        self._closed = True
        if self._req_send is not None:
            with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                await self._req_send.aclose()  # ends the runner's `async for`
            self._req_send = None
        if self._tg is not None:
            # Closing req_send ends an idle runner cleanly; but if it's stuck in
            # an in-flight RPC, an SSE read can block ~5min — cancel its scope so
            # teardown can't stall sibling upstreams. _run catches the cancel.
            self._tg.cancel_scope.cancel()
            self._tg = None
        if self._stack is not None:
            stack, self._stack = self._stack, None
            try:
                await stack.aclose()  # exits the task group; awaits the runner
            except Exception as exc:  # noqa: BLE001 - cleanup must never propagate
                log.warning("closing upstream %r raised %s", self.name, type(exc).__name__)

    async def aclose(self) -> None:
        await self._shutdown()


def build_upstream(name: str, config: UpstreamConfig) -> UpstreamTransport:
    """Construct the transport matching a server config's type (N1)."""
    if isinstance(config, StdioUpstreamConfig):
        return StdioUpstream(name, config)
    if isinstance(config, HttpUpstreamConfig):
        return HttpUpstream(name, config)
    # Unreachable: config is the StdioUpstreamConfig | HttpUpstreamConfig union.
    raise UpstreamError(f"upstream {name!r}: unsupported transport config")
