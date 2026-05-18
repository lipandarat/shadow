"""Shadow CLI entry point."""
import argparse


def main():
    parser = argparse.ArgumentParser(
        prog="shadow",
        description="Shadow - Bug bounty hunting assistant",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    # Subcommands will be added in Plan 7
    args = parser.parse_args()


if __name__ == "__main__":
    main()
