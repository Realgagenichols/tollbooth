"""A minimal but real OAuth 2.0 authorization server + protected MCP resource,
served over HTTP for N2 integration tests (no mocking of the SDK flow).

One Starlette app combines a real FastMCP echo server (mounted at /mcp, gated
by a bearer the AS issued) with the OAuth endpoints the SDK's
`OAuthClientProvider` drives:

- `/.well-known/oauth-protected-resource[/mcp]` — RFC 9728 resource metadata
- `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`
- `POST /register` — dynamic client registration
- `GET  /authorize` — redirects to the loopback redirect_uri with code+state
- `POST /token` — authorization_code and refresh_token grants

The gate returns 401 (with a WWW-Authenticate pointing at the resource
metadata) for an /mcp request lacking an issued token, which is what triggers
the provider's discovery → register → authorize flow.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

from tests.http_echo_server import make_app


@dataclass
class FakeAuthState:
    """Mutable AS state + counters tests assert on."""

    issued_access_tokens: set[str] = field(default_factory=set)
    issued_refresh_tokens: set[str] = field(default_factory=set)
    auth_codes: dict[str, dict[str, str]] = field(default_factory=dict)
    client_id: str | None = None
    code_grants: int = 0
    refresh_grants: int = 0

    def issue(self) -> dict[str, object]:
        """Mint a fresh access+refresh token pair and remember both."""
        access = "at-" + secrets.token_hex(8)
        refresh = "rt-" + secrets.token_hex(8)
        self.issued_access_tokens.add(access)
        self.issued_refresh_tokens.add(refresh)
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh,
        }


def _pkce_ok(verifier: str, challenge: str | None) -> bool:
    if challenge is None:
        return True  # PKCE not exercised by this code path
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(expected, challenge)


class _BearerGate(BaseHTTPMiddleware):
    """401 any /mcp request without a token the AS issued (triggers the flow)."""

    def __init__(self, app, state: FakeAuthState, base_url: str):
        super().__init__(app)
        self.state = state
        self.base_url = base_url

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/mcp"):
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            if token not in self.state.issued_access_tokens:
                prm = f"{self.base_url}/.well-known/oauth-protected-resource"
                return JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{prm}"'},
                )
        return await call_next(request)


def build_fake_oauth_app(base_url: str, state: FakeAuthState) -> Starlette:
    async def prm(_: Request) -> JSONResponse:
        return JSONResponse(
            {"resource": f"{base_url}/mcp", "authorization_servers": [base_url]}
        )

    async def asm(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "issuer": base_url,
                "authorization_endpoint": f"{base_url}/authorize",
                "token_endpoint": f"{base_url}/token",
                "registration_endpoint": f"{base_url}/register",
            }
        )

    async def register(request: Request) -> JSONResponse:
        body = await request.json()
        state.client_id = "client-" + secrets.token_hex(4)
        return JSONResponse(
            {
                **body,
                "client_id": state.client_id,
                "client_secret": "secret-" + secrets.token_hex(4),
            },
            status_code=201,
        )

    async def authorize(request: Request) -> RedirectResponse:
        q = request.query_params
        code = secrets.token_urlsafe(8)
        state.auth_codes[code] = {
            "state": q["state"],
            "challenge": q.get("code_challenge"),
            "redirect_uri": q["redirect_uri"],
        }
        return RedirectResponse(
            f"{q['redirect_uri']}?code={code}&state={q['state']}", status_code=302
        )

    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        grant = form.get("grant_type")
        if grant == "authorization_code":
            record = state.auth_codes.pop(form.get("code", ""), None)
            if record is None or not _pkce_ok(
                form.get("code_verifier", ""), record.get("challenge")
            ):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            state.code_grants += 1
        elif grant == "refresh_token":
            if form.get("refresh_token") not in state.issued_refresh_tokens:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            state.refresh_grants += 1
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        return JSONResponse(state.issue())

    mcp_app = make_app().streamable_http_app()
    routes = [
        Route("/.well-known/oauth-protected-resource", prm),
        Route("/.well-known/oauth-protected-resource/mcp", prm),
        Route("/.well-known/oauth-authorization-server", asm),
        Route("/.well-known/openid-configuration", asm),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize),
        Route("/token", token, methods=["POST"]),
        Mount("/", app=mcp_app),
    ]
    app = Starlette(routes=routes, lifespan=mcp_app.router.lifespan_context)
    app.add_middleware(_BearerGate, state=state, base_url=base_url)
    return app
