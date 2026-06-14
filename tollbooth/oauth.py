"""OAuth 2.0 authentication for HTTP upstreams (N2).

The SDK's ``OAuthClientProvider`` is an ``httpx.Auth`` that drives the full
auth-code + PKCE flow (discovery, dynamic client registration, token exchange,
silent refresh). We supply two things around it:

- ``FileTokenStorage`` — an on-disk ``TokenStorage`` (0600 files, 0700 dir).
  Read back as external input (Pattern 13): tampered permissions or contents
  are rejected so a swapped store is never trusted.
- handlers — a real browser+loopback pair for interactive ``auth login`` and a
  fail-closed pair for unattended ``run`` (which must never open a browser).

Secret hygiene (Pattern 11): access/refresh tokens, auth codes, and client
secrets never appear in logs or error messages.
"""

import json
import logging
import os
import stat
import tempfile
import threading
import time
import webbrowser
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import anyio
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from tollbooth.config import OAuthConfig

log = logging.getLogger(__name__)

CALLBACK_PATH = "/callback"
CALLBACK_TIMEOUT = 300.0  # seconds to wait for the browser redirect


class FailClosedReauth(Exception):
    """Raised in unattended (`run`) mode when a flow would need interactive
    re-authentication. The upstream catches it and fails closed (N2)."""


class OAuthFlowError(Exception):
    """An interactive `auth login` flow could not complete; message is
    user-facing and SHALL NOT contain codes/tokens."""


class TokenStorageError(Exception):
    """The on-disk OAuth credential store is unusable; message is user-facing
    and SHALL NOT contain file contents (only path/reason)."""


def oauth_storage_dir() -> Path:
    """`$XDG_DATA_HOME/tollbooth/oauth` (default `~/.local/share/...`)."""
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "tollbooth" / "oauth"


@dataclass
class _Stored:
    """The on-disk document for one server's credentials."""

    tokens: OAuthToken | None = None
    client_info: OAuthClientInformationFull | None = None
    obtained_at: str | None = None  # ISO-8601; set when tokens are written


class FileTokenStorage:
    """On-disk `TokenStorage` for one upstream server (N2).

    `strict=True` (the `run` path) rejects a store with loose permissions or
    malformed contents — fail closed, never trust it. `strict=False` (the
    `auth login` path) treats such a store as absent so the flow overwrites it.
    """

    def __init__(self, server_name: str, *, strict: bool = True):
        self.server_name = server_name
        self.strict = strict
        self._dir = oauth_storage_dir()
        self._path = self._safe_path(server_name)

    def _safe_path(self, server_name: str) -> Path:
        """`<dir>/<server>.json`, guarding against path traversal in the name.

        The name must be a single path component (no separators, not `.`/`..`)
        so the result is always directly inside the oauth dir. We do NOT
        `.resolve()` the file — that would follow a planted symlink, defeating
        the lstat symlink check in `_check_perms`.
        """
        if (
            not server_name
            or server_name in (".", "..")
            or os.sep in server_name
            or (os.altsep and os.altsep in server_name)
        ):
            # The name is config, not a secret — naming it is what's actionable.
            raise TokenStorageError(
                f"server name {server_name!r} is not a valid credential filename"
            )
        return self._dir / f"{server_name}.json"

    @property
    def path(self) -> Path:
        return self._path

    # --- TokenStorage protocol --------------------------------------------

    async def get_tokens(self) -> OAuthToken | None:
        return self._load().tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        stored = self._load(for_write=True)
        stored.tokens = tokens
        stored.obtained_at = datetime.now(UTC).isoformat()
        self._write(stored)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._load().client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        stored = self._load(for_write=True)
        stored.client_info = client_info
        self._write(stored)

    # --- read / write ------------------------------------------------------

    def _load(self, *, for_write: bool = False) -> _Stored:
        """Read the store, treating it as external input (Pattern 13).

        A missing file is empty. Loose permissions or malformed contents:
        `strict` raises (run fails closed); otherwise returns empty. When
        reading to merge for a write, a rejected file is always treated as
        empty so the write proceeds (and re-establishes 0600).
        """
        if not self._path.exists():
            return _Stored()
        try:
            self._check_perms()
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise TokenStorageError("credential store is not a JSON object")
            tokens = raw.get("tokens")
            client_info = raw.get("client_info")
            return _Stored(
                tokens=OAuthToken.model_validate(tokens) if tokens else None,
                client_info=(
                    OAuthClientInformationFull.model_validate(client_info)
                    if client_info
                    else None
                ),
                obtained_at=raw.get("obtained_at"),
            )
        except (TokenStorageError, json.JSONDecodeError, ValueError) as exc:
            # Never echo the parsed content (it holds tokens) — reason/type only.
            reason = (
                str(exc)
                if isinstance(exc, TokenStorageError)
                else f"unreadable credential store ({type(exc).__name__})"
            )
            if self.strict and not for_write:
                raise TokenStorageError(
                    f"credential store {self._path} for server "
                    f"{self.server_name!r} rejected: {reason}"
                ) from None
            log.warning(
                "ignoring credential store for %r: %s", self.server_name, reason
            )
            return _Stored()

    def _check_perms(self) -> None:
        """Reject an untrusted store (Pattern 13): a symlink (we only trust a
        file we wrote in place), or anything readable/writable by group/other.
        `lstat` so a symlink is judged on its own, not its target."""
        for target in (self._path, self._dir):
            st = target.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise TokenStorageError(f"{target} is a symlink — not trusted")
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o077:
                raise TokenStorageError(
                    f"{target} has insecure permissions {oct(mode)} "
                    "(expected no group/other access)"
                )

    def _write(self, stored: _Stored) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, 0o700)  # enforce even if it pre-existed looser
        doc = {
            "obtained_at": stored.obtained_at,
            "tokens": (
                stored.tokens.model_dump(mode="json", exclude_none=True)
                if stored.tokens
                else None
            ),
            "client_info": (
                stored.client_info.model_dump(mode="json", exclude_none=True)
                if stored.client_info
                else None
            ),
        }
        data = json.dumps(doc, indent=2).encode("utf-8")
        # mkstemp creates the file 0600; rename is atomic within the dir.
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp)
            raise

    def delete(self) -> bool:
        """Remove the stored credentials; returns whether a file was deleted."""
        try:
            self._path.unlink()
            return True
        except FileNotFoundError:
            return False

    def token_expiry(self) -> float | None:
        """Absolute epoch when the stored access token expires, or None if
        unknown. The SDK drops expiry on load (it only restores the token
        value), so we recompute it from our `obtained_at` + `expires_in` and
        re-seat it on the provider — otherwise an expired disk token looks
        valid and gets sent instead of refreshed (N2)."""
        stored = self._load()
        if (
            stored.tokens is None
            or stored.tokens.expires_in is None
            or stored.obtained_at is None
        ):
            return None
        try:
            obtained = datetime.fromisoformat(stored.obtained_at)
        except ValueError:
            return None
        return obtained.timestamp() + stored.tokens.expires_in

    def describe(self) -> dict[str, object] | None:
        """Non-secret summary for `auth status`: presence + obtained_at +
        relative `expires_in`. NEVER returns token values."""
        stored = self._load()
        if stored.tokens is None:
            return None
        return {
            "obtained_at": stored.obtained_at,
            "expires_in": stored.tokens.expires_in,
            "has_refresh_token": stored.tokens.refresh_token is not None,
        }


# --- OAuth flow handlers ---------------------------------------------------


async def _failclosed_redirect(authorization_url: str) -> None:
    raise FailClosedReauth()


async def _failclosed_callback() -> tuple[str, str | None]:
    raise FailClosedReauth()


async def _serve_loopback_callback(
    expected_state: str | None, port: int, timeout: float = CALLBACK_TIMEOUT
) -> tuple[str, str | None]:
    """Receive the OAuth redirect on `127.0.0.1:<port>/callback` (single use).

    Validates `state` against `expected_state` (CSRF) and returns
    `(code, state)`. Raises `OAuthFlowError` on a state mismatch, a missing
    code, or a timeout — never echoing the code in the message.
    """
    result: dict[str, str | None] = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            parts = urlsplit(self.path)
            if parts.path != CALLBACK_PATH:
                self._respond(404, "Not found.")
                return
            query = parse_qs(parts.query)
            code = (query.get("code") or [None])[0]
            state = (query.get("state") or [None])[0]
            if not code:
                result["error"] = "missing authorization code"
            elif expected_state is None or state != expected_state:
                # Fail closed on a missing/mismatched state — and also when we
                # have no expected_state yet (callback before redirect): never
                # accept an unverifiable state (CSRF).
                result["error"] = "state mismatch (possible CSRF)"
            else:
                result["code"] = code
                result["state"] = state
            if "code" in result:
                self._respond(200, "Authentication complete — you may close this tab.")
            else:
                self._respond(400, "Authentication failed — you may close this tab.")
            done.set()

        def _respond(self, status: int, message: str) -> None:
            body = message.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass  # never log the request line — it carries code/state

    def _serve() -> None:
        # Bind 127.0.0.1 ONLY — the redirect must never be reachable off-host.
        server = HTTPServer(("127.0.0.1", port), Handler)
        server.timeout = 1.0
        deadline = time.monotonic() + timeout
        try:
            while not done.is_set() and time.monotonic() < deadline:
                server.handle_request()  # returns after 1s if idle
        finally:
            server.server_close()

    await anyio.to_thread.run_sync(_serve)
    if "code" in result:
        return result["code"], result["state"]
    raise OAuthFlowError(result.get("error") or "timed out waiting for the OAuth redirect")


class _LoopbackAuth:
    """Interactive handler pair: open the browser, then capture the redirect.

    The provider generates `state` and embeds it in the authorization URL; we
    parse it during the redirect step so the callback can validate it (CSRF).
    """

    def __init__(self, port: int):
        self.port = port
        self.expected_state: str | None = None

    async def redirect(self, authorization_url: str) -> None:
        parts = urlsplit(authorization_url)
        self.expected_state = (parse_qs(parts.query).get("state") or [None])[0]
        # Origin only — the full URL carries state and the PKCE challenge.
        log.info(
            "opening browser for OAuth authorization (%s://%s)",
            parts.scheme,
            parts.hostname or "",
        )
        webbrowser.open(authorization_url)

    async def callback(self) -> tuple[str, str | None]:
        return await _serve_loopback_callback(self.expected_state, self.port)


# --- provider factory ------------------------------------------------------


def build_oauth_provider(
    server_name: str, http_url: str, config: OAuthConfig, *, interactive: bool
) -> OAuthClientProvider:
    """Construct the SDK `OAuthClientProvider` for one HTTP upstream (N2).

    `interactive=True` (the `auth login` path) wires the browser+loopback
    handlers and a lenient store (overwrites a rejected file). `interactive=
    False` (the `run` path) wires fail-closed handlers and a strict store, so
    an unattended gateway never opens a browser and fails closed instead.
    """
    redirect_uri = f"http://127.0.0.1:{config.callback_port}{CALLBACK_PATH}"
    metadata = OAuthClientMetadata(
        redirect_uris=[redirect_uri],
        client_name="tollbooth",
        # Empty scopes list → an unscoped request (None), per OAuth.
        scope=" ".join(config.scopes) if config.scopes else None,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
    )
    storage = FileTokenStorage(server_name, strict=not interactive)
    if interactive:
        handlers = _LoopbackAuth(config.callback_port)
        redirect_handler, callback_handler = handlers.redirect, handlers.callback
    else:
        redirect_handler, callback_handler = _failclosed_redirect, _failclosed_callback
    provider = OAuthClientProvider(
        server_url=http_url,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    # Re-seat the expiry the SDK doesn't persist across loads (see
    # FileTokenStorage.token_expiry): a still-valid token is sent, an expired
    # one is refreshed, and an unrefreshable one fails closed — none are sent
    # blindly as if valid. `_initialize` later loads the token value but leaves
    # token_expiry_time untouched, so this survives.
    expiry = storage.token_expiry()
    if expiry is not None:
        provider.context.token_expiry_time = expiry
    return provider
