"""Streamable-HTTP MCP server used as a test upstream (N1).

Served on an ephemeral port by the `http_upstream_url` fixture (conftest).
`echo_header` returns a request header back so tests can prove that
HttpUpstream sent a resolved `${ENV_VAR}` header value to the server.

`make_app()` builds a FRESH FastMCP each call: a FastMCP instance caches one
StreamableHTTP session manager, whose `.run()` lifespan may fire only once, so
each served instance needs its own app.
"""

from mcp.server.fastmcp import Context, FastMCP


def make_app() -> FastMCP:
    app = FastMCP("http-echo")

    @app.tool()
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo: {text}"

    @app.tool()
    def leak() -> str:
        """Return a canned fake credential (exercises result-path DLP)."""
        return "creds: AKIAIOSFODNN7EXAMPLE ok"

    @app.tool()
    def echo_header(name: str, ctx: Context) -> str:
        """Return the value of request header `name` (or '<absent>')."""
        request = ctx.request_context.request
        value = request.headers.get(name) if request is not None else None
        return value or "<absent>"

    @app.tool()
    async def slow(seconds: float) -> str:
        """Sleep, to exercise shutdown while a call is in flight."""
        import anyio

        await anyio.sleep(seconds)
        return "done"

    return app
