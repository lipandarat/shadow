"""Shadow CLI entry point."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="shadow",
        description="Shadow - Bug bounty hunting assistant",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # mcp subcommand
    mcp_parser = subparsers.add_parser("mcp", help="MCP server management")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command", metavar="MCP_COMMAND")

    serve_parser = mcp_sub.add_parser("serve", help="Start an MCP server")
    serve_parser.add_argument(
        "server",
        choices=["bounty-platforms", "writeup-search"],
        help="MCP server to start",
    )
    serve_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify server can start without actually serving",
    )

    args = parser.parse_args()

    if args.command == "mcp":
        if args.mcp_command == "serve":
            _cmd_mcp_serve(args.server, dry_run=args.dry_run)
        else:
            mcp_parser.print_help()
    elif args.command is None:
        parser.print_help()


def _cmd_mcp_serve(server_name: str, dry_run: bool = False) -> None:
    if server_name == "bounty-platforms":
        from shadow.mcp.bounty_platforms import BountyPlatformsMCP
        server = BountyPlatformsMCP()
    elif server_name == "writeup-search":
        from shadow.mcp.writeup_search import WriteupSearchMCP
        server = WriteupSearchMCP()
    else:
        print(f"Unknown server: {server_name}", file=sys.stderr)
        sys.exit(1)

    if dry_run:
        result = server.dry_run()
        tools = server.get_tool_names()
        print(f"Server: {server.name}")
        print(f"Tools: {tools}")
        print(f"Dry run: {'OK' if result else 'FAILED'}")
        return

    server.serve()


if __name__ == "__main__":
    main()
