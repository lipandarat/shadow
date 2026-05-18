"""sync command — sync scope from platform."""


def run(platform: str, program: str) -> None:
    print(f"Syncing {program} from {platform}...")
    print("Note: Set API key in ~/.shadow/config.yaml to enable sync")
