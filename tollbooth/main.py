"""tollbooth -- security gateway for AI agent tool traffic."""

import argparse
import hashlib
import json
import logging
import os
import sys
from contextlib import ExitStack
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TextIO

import anyio

from tollbooth.audit import (
    AuditError,
    AuditLogger,
    audit_key_from_env,
    query_events,
    replay_session,
    tail_state,
    verify_chain,
)
from tollbooth.config import (
    ConfigError,
    GatewayConfig,
    emit_client_config,
    import_client_config,
    load_config,
    render_starter_yaml,
)
from tollbooth.hook import emit_hooks_config, run_hook
from tollbooth.pipeline import Pipeline
from tollbooth.plugins import build_interceptors, load_plugins
from tollbooth.proxy import Gateway
from tollbooth.upstream import UpstreamError, build_upstream

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
    emit_parser.add_argument(
        "--claude-hooks",
        action="store_true",
        help="Emit the Claude Code settings.json hooks block instead (R15)",
    )

    hook_parser = subparsers.add_parser(
        "hook", help="Claude Code hook adapter: evaluate one PreToolUse/PostToolUse event"
    )
    hook_sub = hook_parser.add_subparsers(dest="hook_command", required=True)
    for kind, event_name in (("pre", "PreToolUse"), ("post", "PostToolUse")):
        kind_parser = hook_sub.add_parser(
            kind, help=f"Handle a {event_name} event (JSON on stdin)"
        )
        kind_parser.add_argument(
            "-c", "--config", required=True, help="Path to tollbooth.yaml"
        )

    import_parser = subparsers.add_parser(
        "import", help="Bootstrap tollbooth.yaml from an existing MCP client config"
    )
    import_parser.add_argument(
        "client_config", help="Path to mcp.json / claude_desktop_config.json"
    )
    import_parser.add_argument(
        "-o", "--output", default="tollbooth.yaml", help="Where to write the gateway config"
    )

    audit_parser = subparsers.add_parser(
        "audit", help="Inspect the audit log: verify the chain, query, replay"
    )
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)

    verify_parser = audit_sub.add_parser(
        "verify", help="Verify the audit chain (uses TOLLBOOTH_AUDIT_KEY if set)"
    )
    verify_parser.add_argument("--log", required=True, help="Path to the audit JSONL log")

    query_parser = audit_sub.add_parser(
        "query", help="Filter audit events; matching events emitted as JSONL"
    )
    query_parser.add_argument("--log", required=True, help="Path to the audit JSONL log")
    query_parser.add_argument("--server", help="Exact upstream server name")
    query_parser.add_argument("--tool", help="Exact (un-namespaced) tool name")
    query_parser.add_argument(
        "--decision", choices=["allow", "deny", "require-approval"]
    )
    query_parser.add_argument("--session", help="Session id")
    query_parser.add_argument(
        "--since", type=datetime.fromisoformat, metavar="ISO8601",
        help="Inclusive lower bound (naive = UTC)",
    )
    query_parser.add_argument(
        "--until", type=datetime.fromisoformat, metavar="ISO8601",
        help="Inclusive upper bound (naive = UTC)",
    )

    replay_parser = audit_sub.add_parser(
        "replay", help="Render one session's chronological call/result timeline"
    )
    replay_parser.add_argument("session", help="Session id to replay")
    replay_parser.add_argument("--log", required=True, help="Path to the audit JSONL log")

    return parser


def _gateway_version() -> str:
    try:
        return version("tollbooth")
    except PackageNotFoundError:  # running from a source tree without install
        return "unknown"


def _config_digest(config: GatewayConfig) -> str:
    """SHA-256 over the canonical config dump: proves WHICH config was in
    force (R9) without recording contents — env blocks carry secrets."""
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_gateway(
    config: GatewayConfig,
    audit_stream: TextIO,
    *,
    audit_key: bytes | None = None,
    audit_resume: tuple[int, str] | None = None,
) -> Gateway:
    """Wire config into the runtime object graph (pipeline, upstreams, gateway).

    Stage order lives in build_interceptors — shared with the hook adapter.
    A broken plugin raises ConfigError here, before any upstream starts (R13).
    """
    request_interceptors, result_interceptors = build_interceptors(config)
    pipeline = Pipeline(
        request_interceptors=request_interceptors,
        result_interceptors=result_interceptors,
        fail_open=(config.policy.failure_mode == "open"),
        audit=AuditLogger(
            audit_stream,
            key=audit_key,
            resume=audit_resume,
            record=config.audit.record,
            # File-aware mode: re-seed under flock if hook processes (R15)
            # appended since our last write, so one log stays one chain.
            path=config.audit.log,
        ),
    )
    upstreams = {name: build_upstream(name, spec) for name, spec in config.servers.items()}
    return Gateway(upstreams=upstreams, pipeline=pipeline)


async def _serve(
    config: GatewayConfig,
    audit_stream: TextIO,
    audit_key: bytes | None,
    audit_resume: tuple[int, str] | None,
) -> None:
    gateway = build_gateway(
        config, audit_stream, audit_key=audit_key, audit_resume=audit_resume
    )
    gateway.pipeline.audit.session_start(
        gateway_version=_gateway_version(), config_digest=_config_digest(config)
    )
    try:
        await gateway.start_upstreams()
        log.info("gateway up: %d upstream(s), %d rule(s)",
                 len(config.servers), len(config.policy.rules))
        # Make a misconfigured deploy visible: keyed vs unkeyed chain (key
        # itself is never logged).
        log.info(
            "audit chain mode: %s",
            "keyed (hmac-sha256)" if audit_key else "unkeyed (sha256)",
        )
        await gateway.run_stdio()
    finally:
        await gateway.aclose()


def _open_audit_stream(config: GatewayConfig, stack: ExitStack) -> TextIO:
    """Audit destination: append-mode JSONL file, or stderr when unset."""
    if config.audit.log is None:
        return sys.stderr
    try:
        return stack.enter_context(open(config.audit.log, "a", encoding="utf-8"))  # noqa: SIM115
    except OSError as exc:
        # Path-only message; OSError on open never echoes file contents.
        raise ConfigError(f"cannot open audit log {config.audit.log}: {exc}") from exc


def cmd_run(config_path: str) -> int:
    config = load_config(config_path)
    # Seed the chain from an existing log BEFORE opening it for append, so the
    # chain spans gateway restarts (R8).
    audit_resume = tail_state(config.audit.log) if config.audit.log else None
    with ExitStack() as stack:
        audit_stream = _open_audit_stream(config, stack)
        try:
            anyio.run(_serve, config, audit_stream, audit_key_from_env(), audit_resume)
        except UpstreamError as exc:
            print(f"tollbooth: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_validate(config_path: str) -> int:
    config = load_config(config_path)
    # Validation covers plugins too: a config that imports is one that runs.
    load_plugins(config.plugins)
    dlp_state = (
        f"on ({len(config.dlp.overrides)} override(s))" if config.dlp.enabled else "off"
    )
    print(
        f"OK: {len(config.servers)} server(s), {len(config.policy.rules)} rule(s), "
        f"default={config.policy.default}, failure_mode={config.policy.failure_mode}, "
        f"dlp={dlp_state}, plugins={len(config.plugins)}"
    )
    return 0


def cmd_emit_config(config_path: str, claude_hooks: bool = False) -> int:
    emitted = emit_hooks_config(config_path) if claude_hooks else emit_client_config(config_path)
    print(json.dumps(emitted, indent=2))
    return 0


def cmd_import(client_config_path: str, output: str) -> int:
    out_path = Path(output)
    if out_path.exists():
        # Never clobber an existing gateway config — it IS the security boundary.
        raise ConfigError(f"refusing to overwrite existing {out_path}; move it first")
    config, skipped = import_client_config(client_config_path)
    try:
        # O_EXCL closes the check-then-write race; 0600 because the file may
        # carry env-block secrets copied from the client config.
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(render_starter_yaml(config))
    except OSError as exc:
        # Path-only message; OSError on open/write never echoes file contents.
        raise ConfigError(f"cannot write {out_path}: {exc}") from exc
    print(f"wrote {out_path}: {len(config.servers)} upstream server(s), dlp=on")
    for name in skipped:
        print(f"skipped {name!r}: no command (non-stdio servers land in N1)", file=sys.stderr)
    return 0


def cmd_audit_verify(log_path: str) -> int:
    key = audit_key_from_env()
    try:
        head = verify_chain(log_path, key=key)
    except AuditError as exc:
        # Tampered/unreadable log is a finding (exit 1), not a usage error (2).
        print(f"tollbooth: {exc}", file=sys.stderr)
        return 1
    mode = "hmac-sha256 (keyed)" if key else "sha256 (unkeyed)"
    if head.seq is None:
        print(f"OK: 0 events, mode={mode}")
    else:
        print(
            f"OK: {head.events} event(s), head seq={head.seq} hash={head.digest}, "
            f"mode={mode}"
        )
        print(
            "record the head externally: a log truncated back to an earlier "
            "event still verifies",
            file=sys.stderr,
        )
    return 0


def cmd_audit_query(args: argparse.Namespace) -> int:
    try:
        matched = query_events(
            args.log,
            server=args.server,
            tool=args.tool,
            decision=args.decision,
            session=args.session,
            since=args.since,
            until=args.until,
        )
    except AuditError as exc:
        print(f"tollbooth: {exc}", file=sys.stderr)
        return 1
    for event in matched:
        print(json.dumps(event, ensure_ascii=False))
    return 0


def cmd_audit_replay(args: argparse.Namespace) -> int:
    try:
        print(replay_session(args.log, args.session))
    except AuditError as exc:
        print(f"tollbooth: {exc}", file=sys.stderr)
        return 1
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

    try:
        if args.command == "import":
            code = cmd_import(args.client_config, args.output)
        elif args.command == "hook":
            # run_hook handles its own failures: any error becomes a blocking
            # JSON verdict on stdout (fail-closed), never a bare exit code.
            code = run_hook(args.hook_command, args.config, sys.stdin, sys.stdout)
        elif args.command == "emit-config":
            code = cmd_emit_config(args.config, claude_hooks=args.claude_hooks)
        elif args.command == "audit":
            audit_commands = {
                "verify": lambda a: cmd_audit_verify(a.log),
                "query": cmd_audit_query,
                "replay": cmd_audit_replay,
            }
            code = audit_commands[args.audit_command](args)
        else:
            commands = {"run": cmd_run, "validate": cmd_validate}
            code = commands[args.command](args.config)
    except (ConfigError, AuditError) as exc:
        print(f"tollbooth: {exc}", file=sys.stderr)
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
