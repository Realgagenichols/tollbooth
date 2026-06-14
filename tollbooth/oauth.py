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
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

log = logging.getLogger(__name__)


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
