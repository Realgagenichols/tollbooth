"""Reference prompt-injection detector — a tollbooth plugin example (R14).

NOT a production detector: the heuristics are a tiny, easily bypassed phrase
list, and prompt-injection detection quality is explicitly out of scope for
v1. This module exists to demonstrate that an injection detector slots into
the public plugin API (a result-path interceptor that can block or annotate
suspicious tool results).

Declare it in tollbooth.yaml (the module must be importable where the
gateway runs):

    plugins:
      - plugin: examples.plugins.prompt_injection:create
        settings:
          action: annotate   # or: block
"""

import re

from tollbooth import BlockResult, ResultEdit, ToolCall

# Instruction-override phrasings an injected tool result might carry.
# \W+ between words tolerates punctuation/whitespace tricks; case-insensitive.
_HEURISTICS: tuple[tuple[str, str], ...] = (
    (
        "ignore-previous-instructions",
        r"(?:ignore|disregard|forget)\W+(?:all\W+)?(?:previous|prior|above|earlier)"
        r"\W+instructions",
    ),
    (
        "override-system-prompt",
        r"(?:override|ignore|reveal|leak)\W+(?:the\W+)?system\W+prompt",
    ),
    ("system-tag-smuggling", r"\[\s*system\s*\]|<\s*system\s*>"),
    ("do-anything-now", r"you\W+are\W+now\W+(?:dan|unrestricted|jailbroken)"),
)

_ACTIONS = ("annotate", "block")


class PromptInjectionDetector:
    """Result interceptor: flag instruction-override phrases in tool results.

    action="annotate" (default) prepends a visible warning so the model and
    user see the result is suspect; action="block" withholds it entirely.
    Annotate is the default because heuristics this thin produce false
    positives, and a blocked result is a broken agent.
    """

    name = "prompt-injection"

    def __init__(self, action: str):
        if action not in _ACTIONS:
            # Enum-like options raise at construction — a typo'd action must
            # not silently fall back to permissive behavior (lessons.md).
            raise ValueError(f"unknown action {action!r}: expected one of {_ACTIONS}")
        self.action = action
        self._patterns = [(pid, re.compile(rx, re.IGNORECASE)) for pid, rx in _HEURISTICS]

    def check_result(self, call: ToolCall, content: str) -> ResultEdit:
        hits = tuple(pid for pid, rx in self._patterns if rx.search(content))
        if not hits:
            return ResultEdit(content=content)
        if self.action == "block":
            raise BlockResult(f"prompt-injection:{hits[0]}")
        marker = f"[tollbooth: possible prompt-injection ({','.join(hits)})]"
        return ResultEdit(
            content=f"{marker}\n{content}",
            reason_ids=tuple(f"prompt-injection:{pid}" for pid in hits),
        )


def create(settings: dict) -> PromptInjectionDetector:
    return PromptInjectionDetector(action=settings.get("action", "annotate"))
