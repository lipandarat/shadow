"""Bugcrowd API client stub."""

from shadow.platforms.base import BasePlatform, ProgramInfo, HacktivityEntry
from typing import Optional


class BugcrowdAPI(BasePlatform):
    def __init__(self, api_key: str = None, **kwargs):
        super().__init__(api_key=api_key)

    def sync_program(self, slug: str) -> ProgramInfo:
        return ProgramInfo(slug=slug, name=slug, platform="bugcrowd")

    def list_programs(self) -> list:
        return []

    def get_hacktivity(self, slug: str, limit: int = 20) -> list:
        return []

    def search_hacktivity(self, finding) -> Optional[HacktivityEntry]:
        return None
