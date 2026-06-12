"""Gateway configuration: load + validate tollbooth.yaml, emit client config."""

import json
import shutil
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from tollbooth.dlp import PATTERN_IDS
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


class DlpOverride(BaseModel):
    """Per-pattern action overrides; unset directions keep the defaults (R7)."""

    model_config = ConfigDict(extra="forbid")

    requests: Literal["block", "allow"] | None = None
    results: Literal["redact", "block", "allow"] | None = None


class DlpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    overrides: dict[str, DlpOverride] = {}

    @model_validator(mode="after")
    def _known_pattern_ids(self) -> "DlpConfig":
        unknown = sorted(set(self.overrides) - PATTERN_IDS)
        if unknown:
            raise ValueError(f"unknown DLP pattern id(s): {', '.join(unknown)}")
        return self

    def request_overrides(self) -> dict[str, str]:
        return {p: o.requests for p, o in self.overrides.items() if o.requests is not None}

    def result_overrides(self) -> dict[str, str]:
        return {p: o.results for p, o in self.overrides.items() if o.results is not None}


class AuditConfig(BaseModel):
    """The audit: block (S1, R10).

    record="full" additionally records POST-ENFORCEMENT payloads: arguments
    of allowed requests and result content after redaction — never blocked
    traffic. The default records no argument/result values at all.
    """

    model_config = ConfigDict(extra="forbid")

    # JSONL destination; None = stderr alongside the log lines.
    log: str | None = None
    record: Literal["metadata", "full"] = "metadata"


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: dict[str, UpstreamConfig]
    policy: PolicyConfig = PolicyConfig()
    dlp: DlpConfig = DlpConfig()
    audit: AuditConfig = AuditConfig()
    # Pre-M3 alias for audit.log; normalized below, rejected if both are set.
    audit_log: str | None = None

    @model_validator(mode="after")
    def _normalize_audit_log(self) -> "GatewayConfig":
        if self.audit_log is not None:
            if self.audit.log is not None:
                raise ValueError("set audit.log or audit_log, not both")
            self.audit.log = self.audit_log
        return self


def _validate_gateway_config(raw: object, source: str) -> GatewayConfig:
    """Validate raw data into a GatewayConfig with a sanitized error.

    Pattern 11 applies per model_validate CALL SITE: the raw ValidationError
    rendering includes input_value, which would echo secrets from env blocks.
    Every validation of external input must go through this helper.
    """
    try:
        return GatewayConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"invalid {source}: {details}") from exc


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

    config = _validate_gateway_config(raw, source=f"config {path}")

    for rule in config.policy.rules:
        if rule.server != "*" and rule.server not in config.servers:
            raise ConfigError(
                f"invalid config {path}: rule {rule.name!r} references "
                f"undefined server {rule.server!r}"
            )
    return config


def import_client_config(path: str | Path) -> tuple[GatewayConfig, list[str]]:
    """Build a starter gateway config from an MCP client config (S2).

    Accepts the `mcpServers` (Claude Desktop / .mcp.json) or `servers`
    (VS Code mcp.json) layout. Returns the validated config plus the names
    of skipped non-stdio entries (no `command`, e.g. HTTP servers — N1).
    """
    path = Path(path)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read client config {path}: {exc}") from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        # JSONDecodeError messages are coordinates only — safe to interpolate.
        raise ConfigError(f"malformed JSON in {path}: {exc}") from exc

    # `or` (not .get default) so an empty mcpServers falls through to servers.
    entries = (raw.get("mcpServers") or raw.get("servers")) if isinstance(raw, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise ConfigError(
            f"no MCP servers found in {path}: expected a non-empty "
            "'mcpServers' or 'servers' mapping"
        )

    servers: dict[str, dict] = {}
    skipped: list[str] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict) or "command" not in entry:
            skipped.append(name)
            continue
        servers[name] = {
            "command": entry["command"],
            "args": entry.get("args", []),
            "env": entry.get("env", {}),
        }
    if not servers:
        raise ConfigError(f"no stdio servers in {path}: all entries lack a 'command'")

    config = _validate_gateway_config(
        {
            # Permissive starter: everything allowed, DLP on — tighten from here.
            "servers": servers,
            "policy": {"default": "allow", "rules": []},
            "dlp": {"enabled": True},
        },
        source=f"server entries in {path}",
    )
    return config, skipped


def render_starter_yaml(config: GatewayConfig) -> str:
    """Serialize an imported starter config as commented YAML.

    Keys are rendered explicitly (not via model_dump) so the security knobs
    a user should tune — default decision, failure mode, dlp — stay visible
    even at their default values.
    """
    servers = {}
    for name, spec in config.servers.items():
        entry: dict[str, object] = {"command": spec.command}
        if spec.args:
            entry["args"] = spec.args
        if spec.env:
            entry["env"] = spec.env
        servers[name] = entry
    data = {
        "servers": servers,
        "policy": {
            "default": str(config.policy.default),
            "failure_mode": config.policy.failure_mode,
            "rules": [],
        },
        "dlp": {"enabled": config.dlp.enabled},
    }
    body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    return (
        "# tollbooth.yaml — generated by `tollbooth import`\n"
        "# Starter policy is permissive (default: allow) with DLP enabled.\n"
        "# Add deny/require-approval rules under policy.rules to tighten.\n"
        f"{body}"
    )


def _gateway_command() -> str:
    """Absolute path to the tollbooth binary, for the emitted client config.

    MCP clients spawn servers with a minimal environment — a venv-installed
    `tollbooth` is not on their PATH, so a bare command name would not start.
    """
    argv0 = Path(sys.argv[0])
    if argv0.name == "tollbooth" and argv0.exists():
        return str(argv0.resolve())
    found = shutil.which("tollbooth")
    return found or "tollbooth"


def emit_client_config(path: str | Path) -> dict:
    """Build the MCP client config block routing the client through the gateway.

    Validates the gateway config first so we never emit a pointer to a broken setup.
    """
    path = Path(path)
    load_config(path)
    return {
        "mcpServers": {
            "tollbooth": {
                "command": _gateway_command(),
                "args": ["run", "-c", str(path.resolve())],
            }
        }
    }
