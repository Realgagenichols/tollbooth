"""Policy domain model: decisions, matchers, rules.

Rule evaluation (first-match-wins) is added in section 3; this module owns the
data model so config.py can validate rules without a circular import.
"""

import re
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
