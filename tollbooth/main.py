"""tollbooth -- A security gateway for AI agents: a transparent MCP proxy that enforces policy, DLP, and audit on every tool call and result.."""

import argparse
import logging

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tollbooth",
        description="A security gateway for AI agents: a transparent MCP proxy that enforces policy, DLP, and audit on every tool call and result.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Example subcommand -- replace with real commands
    run_parser = subparsers.add_parser("run", help="Run the main operation")
    run_parser.add_argument("input", help="Input file or value")
    run_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed output",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    if args.command == "run":
        # TODO: implement
        print(f"Processing: {args.input}")


if __name__ == "__main__":
    main()
