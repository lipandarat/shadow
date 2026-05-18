"""Shadow CLI entry point — full command routing."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="shadow",
        description="Shadow - Bug bounty hunting assistant",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # new
    p = subparsers.add_parser("new", help="Create a new engagement workspace")
    p.add_argument("platform", help="Platform: hackerone or bugcrowd")
    p.add_argument("program", help="Program slug")

    # sync
    p = subparsers.add_parser("sync", help="Sync scope from platform")
    p.add_argument("platform", help="Platform: hackerone or bugcrowd")
    p.add_argument("program", help="Program slug")

    # hunt
    p = subparsers.add_parser("hunt", help="Run vulnerability hunt")
    p.add_argument("target", help="Target URL or domain")
    p.add_argument("--vuln-class", help="Vulnerability class to focus on")
    p.add_argument("--resume", action="store_true", help="Resume previous hunt")

    # validate
    p = subparsers.add_parser("validate", help="Validate a finding through 9-question gate")
    p.add_argument("finding_id", help="Finding ID (e.g. F001)")

    # chain
    p = subparsers.add_parser("chain", help="Build exploit chain from a finding")
    p.add_argument("finding_id", help="Root finding ID")

    # report
    p = subparsers.add_parser("report", help="Generate bug bounty report")
    p.add_argument("--format", choices=["md", "yaml"], default="md")

    # dupcheck
    p = subparsers.add_parser("dupcheck", help="Check for duplicate findings")
    p.add_argument("finding_id", help="Finding ID to check")

    # learn
    p = subparsers.add_parser("learn", help="Record platform response for a finding")
    p.add_argument("finding_id", help="Finding ID")
    p.add_argument("status", choices=["accepted", "duplicate", "informational", "not_applicable"])
    p.add_argument("--bounty", type=float, help="Bounty amount awarded")
    p.add_argument("--vuln-type", help="Vulnerability type")

    # oob
    p = subparsers.add_parser("oob", help="Manage OOB listener")
    p.add_argument("action", choices=["start", "stop", "check"])

    # mcp
    mcp_parser = subparsers.add_parser("mcp", help="MCP server management")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command", metavar="MCP_COMMAND")
    serve_parser = mcp_sub.add_parser("serve", help="Start an MCP server")
    serve_parser.add_argument("server", choices=["bounty-platforms", "writeup-search"])
    serve_parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.command == "new":
        from shadow.cli.commands.new import run
        run(args.platform, args.program)
    elif args.command == "sync":
        from shadow.cli.commands.sync import run
        run(args.platform, args.program)
    elif args.command == "hunt":
        from shadow.cli.commands.hunt import run
        run(args.target, vuln_class=args.vuln_class, resume=args.resume)
    elif args.command == "validate":
        from shadow.cli.commands.validate import run
        run(args.finding_id)
    elif args.command == "chain":
        from shadow.cli.commands.chain import run
        run(args.finding_id)
    elif args.command == "report":
        from shadow.cli.commands.report import run
        run(fmt=args.format)
    elif args.command == "dupcheck":
        from shadow.cli.commands.dupcheck import run
        run(args.finding_id)
    elif args.command == "learn":
        from shadow.cli.commands.learn import run
        run(args.finding_id, args.status, bounty=args.bounty, vuln_type=args.vuln_type)
    elif args.command == "oob":
        from shadow.cli.commands.oob import run
        run(args.action)
    elif args.command == "mcp":
        if args.mcp_command == "serve":
            _cmd_mcp_serve(args.server, dry_run=args.dry_run)
        else:
            mcp_parser.print_help()
    else:
        parser.print_help()


def _cmd_mcp_serve(server_name: str, dry_run: bool = False) -> None:
    if server_name == "bounty-platforms":
        from shadow.mcp.bounty_platforms import BountyPlatformsMCP
        server = BountyPlatformsMCP()
    else:
        from shadow.mcp.writeup_search import WriteupSearchMCP
        server = WriteupSearchMCP()

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
