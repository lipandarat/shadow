"""Bugcrowd API client."""

import httpx
from typing import Optional
from shadow.platforms.base import BasePlatform, PlatformError, ProgramInfo, ProgramScope, HacktivityEntry


class BugcrowdAPI(BasePlatform):
    BASE_URL = "https://api.bugcrowd.com"

    def sync_program(self, slug: str) -> ProgramInfo:
        self._require_api_key()
        resp = self._get(f"/programs/{slug}")
        data = resp.get("program", resp.get("data", {}))
        scope = self._parse_scope(data)
        return ProgramInfo(
            slug=slug,
            name=data.get("name", slug),
            platform="bugcrowd",
            scope=scope,
            submission_state=data.get("program_state", "open"),
            url=f"https://bugcrowd.com/{slug}",
        )

    def list_programs(self) -> list[ProgramInfo]:
        self._require_api_key()
        resp = self._get("/programs", params={"page[limit]": 25})
        programs = []
        for item in resp.get("programs", resp.get("data", [])):
            programs.append(ProgramInfo(
                slug=item.get("code", item.get("slug", "")),
                name=item.get("name", ""),
                platform="bugcrowd",
                submission_state=item.get("program_state", "open"),
                url=f"https://bugcrowd.com/{item.get('code', '')}",
            ))
        return programs

    def get_hacktivity(self, slug: str, limit: int = 20) -> list[HacktivityEntry]:
        resp = self._get("/disclosures", params={
            "program": slug,
            "page[limit]": limit,
        })
        entries = []
        for item in resp.get("disclosures", resp.get("data", [])):
            vuln_refs = item.get("vulnerability_references", [])
            vuln_type = vuln_refs[0].get("name", "unknown") if vuln_refs else "unknown"
            entries.append(HacktivityEntry(
                title=item.get("title", ""),
                url=item.get("url", ""),
                severity=item.get("severity", "unknown"),
                vuln_type=vuln_type,
                bounty=item.get("paid_amount"),
                disclosed_at=item.get("disclosed_at", ""),
                program=slug,
            ))
        return entries

    def search_hacktivity(self, finding) -> Optional[HacktivityEntry]:
        try:
            entries = self.get_hacktivity("", limit=50)
            vuln_lower = finding.vuln_class.lower()
            for entry in entries:
                if vuln_lower in entry.vuln_type.lower() or vuln_lower in entry.title.lower():
                    return entry
        except Exception:
            pass
        return None

    def _parse_scope(self, data: dict) -> ProgramScope:
        scope = ProgramScope()
        targets = data.get("targets", {}).get("in_scope", [])
        out_of_scope = data.get("targets", {}).get("out_of_scope", [])
        for t in targets:
            target = t.get("target", "")
            if target.startswith("*."):
                scope.wildcards.append(target)
                scope.domains.append(target[2:])
            elif target:
                scope.domains.append(target)
        for t in out_of_scope:
            target = t.get("target", "")
            if target:
                scope.excluded.append(target)
        return scope

    def _get(self, path: str, params: dict = None) -> dict:
        url = self.BASE_URL + path
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"
        try:
            resp = httpx.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise PlatformError(f"Bugcrowd API error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise PlatformError(f"Bugcrowd request failed: {e}")
