"""Structured audit logging: one JSONL event per gateway decision (S1).

Events record WHAT was decided (server, tool, decision, rule/pattern id) and
never WHY-payloads (argument or content values). M3 makes the log tamper-
evident (R8): every event carries a monotonic `seq` and a `prev` field holding
the SHA-256 hash of the preceding event line, so edits, deletions, and
reordering break the chain.
"""

import hashlib
import hmac
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

SCHEMA_VERSION = 2
# `prev` of the first event in a file. A chain truncated back to its first
# event still verifies — end-truncation is detected by comparing the chain
# head reported by `verify` against an externally recorded head.
GENESIS = "genesis"


class AuditError(Exception):
    """Audit trail problem (unreadable/invalid log). Messages carry the path
    and location, never line contents — a log fed back to us is external
    input that may embed payloads (Pattern 11)."""


def tail_state(path: str | Path) -> tuple[int, str] | None:
    """(seq, raw line) of the last event in an existing log, or None if the
    file is missing or empty. Used to seed the chain when appending (R8)."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditError(f"cannot read audit log {path}: {exc}") from exc
    lines = text.splitlines()
    if not lines:
        return None
    last = lines[-1]
    try:
        seq = json.loads(last)["seq"]
        # bool is an int subclass — a tampered `"seq": true` must not resume.
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise KeyError("seq")
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # Line number + path only — never the line itself (Pattern 11).
        raise AuditError(
            f"cannot resume audit chain: {path} line {len(lines)} "
            "is not a valid audit event"
        ) from exc
    return seq, last


@dataclass(frozen=True)
class ChainHead:
    """Where a verified chain ends. Record (seq, digest) externally to detect
    end-truncation — a chain cut back to any earlier event still verifies."""

    events: int
    seq: int | None  # None for an empty log
    digest: str


def verify_chain(path: str | Path, key: bytes | None = None) -> ChainHead:
    """Validate the audit chain (R8): every line parses, seq is gapless, and
    each `prev` matches the digest of the preceding line. Raises AuditError at
    the first break — naming path/line/seq only, never event contents.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot read audit log {path}: {exc}") from exc

    prev = GENESIS
    expected_seq = 0
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
            seq = event["seq"]
            claimed_prev = event["prev"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AuditError(
                f"audit chain invalid: {path} line {lineno} is not a valid audit event"
            ) from exc
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise AuditError(
                f"audit chain invalid: {path} line {lineno} has an invalid sequence number"
            )
        if seq != expected_seq:
            raise AuditError(
                f"audit chain broken: {path} line {lineno} — expected seq "
                f"{expected_seq}, found {seq} (event deleted or reordered?)"
            )
        if claimed_prev != prev:
            raise AuditError(
                f"audit chain broken: {path} line {lineno} — prev hash mismatch "
                "(an earlier event was modified, deleted, or reordered)"
            )
        prev = _line_digest(line, key)
        expected_seq = seq + 1

    if not lines:
        return ChainHead(events=0, seq=None, digest=GENESIS)
    return ChainHead(events=len(lines), seq=expected_seq - 1, digest=prev)


def audit_key_from_env() -> bytes | None:
    """Chain key from TOLLBOOTH_AUDIT_KEY (env, never a CLI flag). With a key,
    chain hashes are HMAC-SHA-256 — a rewritten file can't forge a valid chain
    without it. The key itself is never logged or echoed."""
    raw = os.environ.get("TOLLBOOTH_AUDIT_KEY")
    return raw.encode("utf-8") if raw else None


def _line_digest(line: str, key: bytes | None) -> str:
    """Chain hash of one event line (no trailing newline), over UTF-8 bytes."""
    data = line.encode("utf-8")
    if key is not None:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


class AuditLogger:
    """Writes one JSON object per line to a text stream; lines form a hash
    chain (R8). seq/prev state is guarded by the same lock that serializes
    writes — concurrent tool calls share one stream (Pattern 8)."""

    def __init__(
        self,
        stream: TextIO,
        *,
        key: bytes | None = None,
        resume: tuple[int, str] | None = None,
    ):
        self._stream = stream
        self._lock = threading.Lock()
        self._key = key  # read once here; never logged (R8)
        # One logger per gateway run, so this IS the session id (R9).
        self.session_id = uuid.uuid4().hex
        if resume is None:
            self._seq = 0
            self._prev = GENESIS
        else:
            last_seq, last_line = resume
            self._seq = last_seq + 1
            self._prev = _line_digest(last_line, key)

    def _emit(self, fields: dict) -> None:
        with self._lock:
            event = {
                "v": SCHEMA_VERSION,
                "ts": datetime.now(UTC).isoformat(),
                "seq": self._seq,
                "prev": self._prev,
                "session": self.session_id,
                **fields,
            }
            line = json.dumps(event, ensure_ascii=False)
            self._stream.write(line + "\n")
            self._stream.flush()
            self._prev = _line_digest(line, self._key)
            self._seq += 1

    def session_start(self, *, gateway_version: str, config_digest: str) -> None:
        """Open a session in the trail (R9): which gateway, under WHICH config
        — recorded as a digest so env-block secrets never reach the log."""
        self._emit(
            {
                "event": "session-start",
                "gateway_version": gateway_version,
                "config_digest": config_digest,
            }
        )

    def decision(
        self,
        *,
        path: str,
        server: str,
        tool: str,
        decision: str,
        reason_id: str | None,
        call_id: str | None = None,
    ) -> None:
        self._emit(
            {
                "event": "decision",
                "call_id": call_id,
                "path": path,
                "server": server,
                "tool": tool,
                "decision": decision,
                "reason_id": reason_id,
            }
        )
