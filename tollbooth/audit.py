"""Structured audit logging: one JSONL event per gateway decision (S1).

Events record WHAT was decided (server, tool, decision, rule/pattern id) and
never WHY-payloads (argument or content values). Expands into the
tamper-evident audit trail in M3.
"""

import json
import threading
from datetime import UTC, datetime
from typing import TextIO


class AuditLogger:
    """Writes one JSON object per line to a text stream."""

    def __init__(self, stream: TextIO):
        self._stream = stream
        # Serialize writes: concurrent tool calls share one stream (Pattern 8).
        self._lock = threading.Lock()

    def decision(
        self,
        *,
        path: str,
        server: str,
        tool: str,
        decision: str,
        reason_id: str | None,
    ) -> None:
        event = {
            "ts": datetime.now(UTC).isoformat(),
            "path": path,
            "server": server,
            "tool": tool,
            "decision": decision,
            "reason_id": reason_id,
        }
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()
