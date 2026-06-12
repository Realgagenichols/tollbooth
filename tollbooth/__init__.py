"""tollbooth — security gateway for AI agent tool traffic.

Public plugin API (R13). A plugin is declared in tollbooth.yaml as a
`module:factory` import spec; the factory receives the plugin's `settings`
dict and returns an interceptor:

- request path: a `name` attribute plus `check_request(call: ToolCall) ->
  PolicyResult` — any non-ALLOW decision short-circuits the call.
- result path: a `name` attribute plus `check_result(call: ToolCall,
  content: str) -> ResultEdit` — return (possibly transformed) content with
  `reason_ids` for audit; raise `BlockResult(reason_id)` to withhold the
  result intentionally; any other exception is a stage failure handled by the
  gateway's fail-closed policy (R4).

An interceptor may implement both. Plugins run AFTER the built-in policy and
DLP stages, in declared order — they can tighten, never pre-empt.
"""

from tollbooth.pipeline import (
    BlockResult,
    RequestInterceptor,
    ResultEdit,
    ResultInterceptor,
    ToolCall,
)
from tollbooth.policy import Decision, PolicyResult

__all__ = [
    "BlockResult",
    "Decision",
    "PolicyResult",
    "RequestInterceptor",
    "ResultEdit",
    "ResultInterceptor",
    "ToolCall",
]
