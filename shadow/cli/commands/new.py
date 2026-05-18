"""new command — create engagement workspace."""
from shadow.core.engagement import EngagementManager


def run(platform: str, program: str) -> None:
    mgr = EngagementManager()
    eng = mgr.create(platform, program)
    print(f"Created engagement: {eng.workspace_path}")
