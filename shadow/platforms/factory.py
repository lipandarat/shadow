"""Platform factory — returns the correct API client for a given platform name."""

from shadow.platforms.base import BasePlatform, PlatformError


def get_platform(platform_name: str, api_key: str = None, **kwargs) -> BasePlatform:
    """Return a platform client instance for the given platform name."""
    name = platform_name.lower().strip()
    if name == "hackerone":
        from shadow.platforms.hackerone import HackerOneAPI
        return HackerOneAPI(api_key=api_key, **kwargs)
    elif name == "bugcrowd":
        from shadow.platforms.bugcrowd import BugcrowdAPI
        return BugcrowdAPI(api_key=api_key, **kwargs)
    else:
        raise ValueError(f"Unknown platform: {platform_name!r}. Supported: hackerone, bugcrowd")


SUPPORTED_PLATFORMS = ["hackerone", "bugcrowd"]
