"""tollbooth -- security gateway for AI agent tool traffic."""

import argparse
import json
import logging
import sys
from contextlib import ExitStack
from typing import TextIO

import anyio

from tollbooth.audit import AuditLogger
from tollbooth.config import ConfigError, GatewayConfig, emit_client_config, load_config
from tollbooth.pipeline import Pipeline, PolicyInterceptor
from tollbooth.proxy import Gateway
from tollbooth.upstream import StdioUpstream, UpstreamError

log = logging.getLogger(__name__)

DESCRIPTION = (
    "A security gateway for AI agents: a transparent MCP proxy that "
    "enforces policy, DLP, and audit on every tool call and result."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tollbooth", description=DESCRIPTION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the gateway (stdio MCP server)")
    run_parser.add_argument("-c", "--config", required=True, help="Path to tollbooth.yaml")

    validate_parser = subparsers.add_parser("validate", help="Validate a gateway config")
    validate_parser.add_argument("-c", "--config", required=True, help="Path to tollbooth.yaml")

    emit_parser = subparsers.add_parser(
        "emit-config", help="Emit the MCP client config pointing at the gateway"
    )
    emit_parser.add_argument("-c", "--config", required=True, help="Path to tollbooth.yaml")

    return parser


def build_gateway(config: GatewayConfig, audit_stream: TextIO) -> Gateway:
    """Wire config into the runtime object graph (pipeline, upstreams, gateway)."""
    pipeline = Pipeline(
        request_interceptors=[
            PolicyInterceptor(rules=config.policy.rules, default=config.policy.default)
        ],
        fail_open=(config.policy.failure_mode == "open"),
        audit=AuditLogger(audit_stream),
    )
    upstreams = {name: StdioUpstream(name, spec) for name, spec in config.servers.items()}
    return Gateway(upstreams=upstreams, pipeline=pipeline)


async def _serve(config: GatewayConfig, audit_stream: TextIO) -> None:
    gateway = build_gateway(config, audit_stream)
    try:
        await gateway.start_upstreams()
        log.info("gateway up: %d upstream(s), %d rule(s)",
                 len(config.servers), len(config.policy.rules))
        await gateway.run_stdio()
    finally:
        await gateway.aclose()


def _open_audit_stream(config: GatewayConfig, stack: ExitStack) -> TextIO:
    """Audit destination: append-mode JSONL file, or stderr when unset."""
    if config.audit_log is None:
        return sys.stderr
    try:
        return stack.enter_context(open(config.audit_log, "a", encoding="utf-8"))  # noqa: SIM115
    except OSError as exc:
        # Path-only message; OSError on open never echoes file contents.
        raise ConfigError(f"cannot open audit log {config.audit_log}: {exc}") from exc


def cmd_run(config_path: str) -> int:
    config = load_config(config_path)
    with ExitStack() as stack:
        audit_stream = _open_audit_stream(config, stack)
        try:
            anyio.run(_serve, config, audit_stream)
        except UpstreamError as exc:
            print(f"tollbooth: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_validate(config_path: str) -> int:
    config = load_config(config_path)
    print(
        f"OK: {len(config.servers)} server(s), {len(config.policy.rules)} rule(s), "
        f"default={config.policy.default}, failure_mode={config.policy.failure_mode}"
    )
    return 0


def cmd_emit_config(config_path: str) -> int:
    print(json.dumps(emit_client_config(config_path), indent=2))
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        # Gateway logs go to stderr: stdout is the MCP transport.
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    commands = {"run": cmd_run, "validate": cmd_validate, "emit-config": cmd_emit_config}
    try:
        code = commands[args.command](args.config)
    except ConfigError as exc:
        print(f"tollbooth: {exc}", file=sys.stderr)
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
