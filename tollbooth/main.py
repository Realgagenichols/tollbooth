"""tollbooth -- security gateway for AI agent tool traffic."""

import argparse
import logging
import sys

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


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        # Gateway logs go to stderr: stdout is the MCP transport.
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "run":
        raise NotImplementedError("implemented in section 8")
    if args.command == "validate":
        raise NotImplementedError("implemented in section 8")
    if args.command == "emit-config":
        raise NotImplementedError("implemented in section 8")


if __name__ == "__main__":
    main()
