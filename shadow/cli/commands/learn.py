"""learn command."""


def run(finding_id: str, status: str, bounty: float = None, vuln_type: str = None) -> None:
    print(f"Recording: {finding_id} -> {status}")
    if bounty:
        print(f"Bounty: ${bounty}")
