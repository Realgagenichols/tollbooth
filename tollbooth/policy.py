"""Policy engine: decisions, matchers, rules, first-match-wins evaluation.

This module owns the rule data model (so config.py can validate rules without
a circular import) and the evaluation logic.
"""

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator


class Decision(StrEnum):
    """Outcome of policy evaluation.

    Extensible by design (R5): future approval channels (TUI, MCP elicitation)
    add members here without reworking the policy model.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require-approval"


_OPERATORS = ("equals", "regex", "prefix", "not_prefix")


class Matcher(BaseModel):
    """A single argument-field matcher: exactly one operator must be set."""

    model_config = ConfigDict(extra="forbid")

    equals: str | None = None
    regex: str | None = None
    prefix: str | None = None
    not_prefix: str | None = None

    @model_validator(mode="after")
    def _exactly_one_operator(self) -> "Matcher":
        set_ops = [op for op in _OPERATORS if getattr(self, op) is not None]
        if len(set_ops) != 1:
            raise ValueError(
                f"matcher must set exactly one of {_OPERATORS}, got {set_ops or 'none'}"
            )
        if self.regex is not None:
            try:
                re.compile(self.regex)
            except re.error as exc:
                raise ValueError(f"invalid regex {self.regex!r}: {exc}") from exc
        return self


class Rule(BaseModel):
    """One policy rule. `server`/`tool` accept exact names or the `*` wildcard."""

    model_config = ConfigDict(extra="forbid")

    name: str
    action: Decision
    server: str = "*"
    tool: str = "*"
    where: dict[str, Matcher] = {}


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of evaluating one tool call. rule_name is None for the default."""

    decision: Decision
    rule_name: str | None
    message: str


def _normalize(value: str) -> str:
    # NFC-normalize both sides so composed vs decomposed unicode compares equal
    # (cross-cutting Pattern 7).
    return unicodedata.normalize("NFC", value)


def _matcher_matches(matcher: Matcher, value: object) -> bool:
    text = _normalize(value if isinstance(value, str) else str(value))
    if matcher.equals is not None:
        return text == _normalize(matcher.equals)
    if matcher.regex is not None:
        return re.search(matcher.regex, text) is not None
    if matcher.prefix is not None:
        return text.startswith(_normalize(matcher.prefix))
    if matcher.not_prefix is not None:
        return not text.startswith(_normalize(matcher.not_prefix))
    raise AssertionError("matcher validated to have exactly one operator")


def _rule_matches(rule: Rule, server: str, tool: str, args: dict[str, object]) -> bool:
    if rule.server != "*" and rule.server != server:
        return False
    if rule.tool != "*" and rule.tool != tool:
        return False
    for field, matcher in rule.where.items():
        if field not in args:
            # A rule conditioned on a field cannot fire when the field is absent.
            return False
        if not _matcher_matches(matcher, args[field]):
            return False
    return True


def _message(decision: Decision, rule_name: str | None, server: str, tool: str) -> str:
    # Messages name the rule and tool but NEVER argument values (S1).
    call = f"{server}/{tool}"
    if decision is Decision.REQUIRE_APPROVAL:
        return (
            f"tollbooth: {call} requires approval (rule {rule_name!r}). "
            "To permit this call, add an allow rule for it in tollbooth.yaml "
            "and restart the gateway."
        )
    if decision is Decision.DENY:
        by = f"policy rule {rule_name!r}" if rule_name else "the default policy"
        return f"tollbooth: {call} denied by {by}."
    by = f"rule {rule_name!r}" if rule_name else "default policy"
    return f"tollbooth: {call} allowed by {by}."


def evaluate(
    server: str,
    tool: str,
    args: dict[str, object],
    rules: list[Rule],
    default: Decision,
) -> PolicyResult:
    """Resolve a tool call to a decision: first matching rule wins (R2)."""
    for rule in rules:
        if _rule_matches(rule, server, tool, args):
            return PolicyResult(
                decision=rule.action,
                rule_name=rule.name,
                message=_message(rule.action, rule.name, server, tool),
            )
    return PolicyResult(
        decision=default,
        rule_name=None,
        message=_message(default, None, server, tool),
    )
