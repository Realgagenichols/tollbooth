"""Minimal stdio MCP server used as a test upstream (run as a subprocess)."""

from mcp.server.fastmcp import FastMCP

app = FastMCP("echo")


@app.tool()
def echo(text: str) -> str:
    """Echo the input back."""
    return f"echo: {text}"


@app.tool()
def shout(text: str) -> str:
    """Uppercase the input."""
    return text.upper()


if __name__ == "__main__":
    app.run()  # stdio transport
