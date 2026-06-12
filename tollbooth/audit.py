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
        if not isinstance(seq, int):
            raise KeyError("seq")
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # Line number + path only — never the line itself (Pattern 11).
        raise AuditError(
            f"cannot resume audit chain: {path} line {len(lines)} "
            "is not a valid audit event"
        ) from exc
    return seq, last


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
                **fields,
            }
            line = json.dumps(event, ensure_ascii=False)
            self._stream.write(line + "\n")
            self._stream.flush()
            self._prev = _line_digest(line, self._key)
            self._seq += 1

    def decision(
        self,
        *,
        path: str,
        server: str,
        tool: str,
        decision: str,
        reason_id: str | None,
    ) -> None:
        self._emit(
            {
                "event": "decision",
                "path": path,
                "server": server,
                "tool": tool,
                "decision": decision,
                "reason_id": reason_id,
            }
        )
