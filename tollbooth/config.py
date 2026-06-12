"""Gateway configuration: load + validate tollbooth.yaml, emit client config."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from tollbooth.policy import Decision, Rule


class ConfigError(Exception):
    """Raised for any configuration problem; message is user-facing."""


def _yaml_error_detail(exc: yaml.YAMLError) -> str:
    """Describe a YAML error without its source snippet (which may hold secrets)."""
    if not isinstance(exc, yaml.MarkedYAMLError):
        return "syntax error"
    parts = [text for text in (exc.context, exc.problem) if text]
    mark = exc.problem_mark
    if mark is not None:
        # Coordinates only — str(mark) would pull in the source snippet.
        parts.append(f"(line {mark.line + 1}, column {mark.column + 1})")
    return " ".join(parts) or "syntax error"


class UpstreamConfig(BaseModel):
    """Launch spec for one upstream stdio MCP server."""

    model_config = ConfigDict(extra="forbid")

    command: str
    args: list[str] = []
    env: dict[str, str] = {}


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: Decision = Decision.ALLOW
    failure_mode: Literal["closed", "open"] = "closed"
    rules: list[Rule] = []


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: dict[str, UpstreamConfig]
    policy: PolicyConfig = PolicyConfig()


def load_config(path: str | Path) -> GatewayConfig:
    """Load and validate a tollbooth.yaml. Raises ConfigError with a clear message."""
    path = Path(path)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        # Never interpolate the exception itself: PyYAML marks embed a snippet
        # of the offending source line, which may contain secrets.
        raise ConfigError(f"malformed YAML in {path}: {_yaml_error_detail(exc)}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"malformed YAML in {path}: top level must be a mapping")

    try:
        config = GatewayConfig.model_validate(raw)
    except ValidationError as exc:
        # Never interpolate the raw ValidationError: its default rendering
        # includes input_value, which would echo secrets from env blocks.
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"invalid config {path}: {details}") from exc

    for rule in config.policy.rules:
        if rule.server != "*" and rule.server not in config.servers:
            raise ConfigError(
                f"invalid config {path}: rule {rule.name!r} references "
                f"undefined server {rule.server!r}"
            )
    return config


def emit_client_config(path: str | Path) -> dict:
    """Build the MCP client config block routing the client through the gateway.

    Validates the gateway config first so we never emit a pointer to a broken setup.
    """
    path = Path(path)
    load_config(path)
    return {
        "mcpServers": {
            "tollbooth": {
                "command": "tollbooth",
                "args": ["run", "-c", str(path.resolve())],
            }
        }
    }
