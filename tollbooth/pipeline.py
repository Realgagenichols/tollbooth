"""Interceptor pipeline: ordered checks on the request and result paths.

Policy (M1) and DLP (M2) are both interceptors on this chain; M4's plugin API
formalizes these protocols. Fail-closed is enforced HERE, once, so individual
interceptors never need their own error policy (R4).
"""

import logging
from dataclasses import dataclass
from typing import Protocol

from tollbooth.policy import Decision, PolicyResult, Rule, evaluate

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation, in upstream terms (server + original tool name)."""

    server: str
    tool: str
    args: dict[str, object]


@dataclass(frozen=True)
class ResultVerdict:
    """Outcome of the result path. content is None when the result is withheld."""

    decision: Decision
    content: str | None
    message: str


class BlockResult(Exception):
    """Raised by a result interceptor to INTENTIONALLY withhold a result.

    Distinct from stage failure: an intentional security verdict is honored
    even in fail-open mode (fail-open bypasses broken stages, never deliberate
    blocks). M2's DLP per-pattern `block` override uses this.
    """

    def __init__(self, reason_id: str):
        # reason_id is a rule/pattern identifier — never detected content.
        super().__init__(reason_id)
        self.reason_id = reason_id


class RequestInterceptor(Protocol):
    name: str

    def check_request(self, call: ToolCall) -> PolicyResult: ...


class ResultInterceptor(Protocol):
    name: str

    def check_result(self, call: ToolCall, content: str) -> str:
        """Return (possibly transformed) content, or raise to signal failure."""
        ...


class PolicyInterceptor:
    """Adapts the policy engine (R2) to the request-interceptor protocol."""

    name = "policy"

    def __init__(self, rules: list[Rule], default: Decision):
        self.rules = rules
        self.default = default

    def check_request(self, call: ToolCall) -> PolicyResult:
        return evaluate(call.server, call.tool, call.args, self.rules, self.default)


class Pipeline:
    """Runs interceptors in order; any non-ALLOW verdict short-circuits.

    failure handling (R4): an interceptor exception denies the call (fail-closed)
    unless fail_open=True, in which case the broken stage is skipped and logged.
    Failure logs name the interceptor and call, NEVER argument values.
    """

    def __init__(
        self,
        request_interceptors: list[RequestInterceptor] | None = None,
        result_interceptors: list[ResultInterceptor] | None = None,
        fail_open: bool = False,
    ):
        self.request_interceptors = request_interceptors or []
        self.result_interceptors = result_interceptors or []
        self.fail_open = fail_open

    def _on_failure(self, stage_name: str, call: ToolCall, exc: Exception) -> bool:
        """Log a stage failure; return True if processing may continue (fail-open)."""
        mode = "failed open" if self.fail_open else "fail-closed"
        log.error(
            "interceptor %r %s on %s/%s: %s",
            stage_name,
            mode,
            call.server,
            call.tool,
            # Exception TYPE only: arbitrary interceptor exceptions may echo
            # argument/content values (e.g. ValidationError input_value) —
            # same leak class as the config.py lesson.
            type(exc).__name__,
        )
        return self.fail_open

    def evaluate_request(self, call: ToolCall) -> PolicyResult:
        for interceptor in self.request_interceptors:
            try:
                result = interceptor.check_request(call)
            except Exception as exc:
                if self._on_failure(interceptor.name, call, exc):
                    continue
                return PolicyResult(
                    decision=Decision.DENY,
                    rule_name=None,
                    message=(
                        f"tollbooth: {call.server}/{call.tool} denied — security check "
                        f"{interceptor.name!r} failed and the gateway is fail-closed."
                    ),
                )
            if result.decision is not Decision.ALLOW:
                return result
        return PolicyResult(
            decision=Decision.ALLOW,
            rule_name=None,
            message=f"tollbooth: {call.server}/{call.tool} allowed.",
        )

    def process_result(self, call: ToolCall, content: str) -> ResultVerdict:
        for interceptor in self.result_interceptors:
            try:
                content = interceptor.check_result(call, content)
            except BlockResult as block:
                # Intentional verdict — honored regardless of fail_open.
                return ResultVerdict(
                    decision=Decision.DENY,
                    content=None,
                    message=(
                        f"tollbooth: result of {call.server}/{call.tool} blocked by "
                        f"security check {interceptor.name!r} ({block.reason_id})."
                    ),
                )
            except Exception as exc:
                if self._on_failure(interceptor.name, call, exc):
                    continue
                return ResultVerdict(
                    decision=Decision.DENY,
                    content=None,
                    message=(
                        f"tollbooth: result of {call.server}/{call.tool} withheld — "
                        f"security check {interceptor.name!r} failed and the gateway "
                        "is fail-closed."
                    ),
                )
        return ResultVerdict(decision=Decision.ALLOW, content=content, message="ok")
