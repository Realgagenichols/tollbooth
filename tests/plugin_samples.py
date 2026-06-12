"""Sample plugins for R13 tests, loaded via `tests.plugin_samples:<factory>`.

Written against the PUBLIC plugin API (top-level `tollbooth` imports) so the
tests double as a check that the documented surface is sufficient to author
a plugin.
"""

from tollbooth import BlockResult, Decision, PolicyResult, ResultEdit, ToolCall

SENTINEL = "sentinel-AKIA-do-not-echo"

NOT_A_FACTORY = "just a string"


class _DenyTool:
    name = "deny-tool"

    def __init__(self, tool: str):
        self.tool = tool

    def check_request(self, call: ToolCall) -> PolicyResult:
        if call.tool == self.tool:
            return PolicyResult(
                decision=Decision.DENY,
                rule_name="plugin:deny-tool",
                message=f"tollbooth: {call.server}/{call.tool} denied by deny-tool plugin.",
            )
        return PolicyResult(decision=Decision.ALLOW, rule_name=None, message="ok")


def deny_tool(settings: dict):
    return _DenyTool(tool=settings.get("tool", "deploy"))


class _AllowAll:
    """Names every allow — exercises allow-reason aggregation in the audit."""

    name = "allow-all"

    def check_request(self, call: ToolCall) -> PolicyResult:
        return PolicyResult(
            decision=Decision.ALLOW, rule_name="plugin:allow-all", message="ok"
        )


def allow_all(settings: dict):
    return _AllowAll()


class _RedactWord:
    name = "redact-word"

    def __init__(self, word: str, block: bool):
        self.word = word
        self.block = block

    def check_result(self, call: ToolCall, content: str) -> ResultEdit:
        if self.word not in content:
            return ResultEdit(content=content)
        if self.block:
            raise BlockResult("plugin:redact-word")
        return ResultEdit(
            content=content.replace(self.word, "[PLUGIN]"),
            reason_ids=("plugin:redact-word",),
        )


def redact_word(settings: dict):
    return _RedactWord(word=settings["word"], block=bool(settings.get("block", False)))


class _Crashy:
    name = "crashy"

    def check_request(self, call: ToolCall) -> PolicyResult:
        raise RuntimeError(SENTINEL)

    def check_result(self, call: ToolCall, content: str) -> ResultEdit:
        raise RuntimeError(SENTINEL)


def crashy(settings: dict):
    return _Crashy()


def boom(settings: dict):
    # Factory failure whose message must never reach the user (Pattern 11).
    raise RuntimeError(SENTINEL)


def no_name(settings: dict):
    class Nameless:
        def check_request(self, call):  # pragma: no cover - never reached
            raise AssertionError

    return Nameless()


def no_checks(settings: dict):
    class Inert:
        name = "inert"

    return Inert()


def reserved_name(settings: dict):
    class Shadow:
        name = "policy"

        def check_request(self, call):  # pragma: no cover - never reached
            raise AssertionError

    return Shadow()
