"""HackerOne API client."""

import base64
import httpx
from typing import Optional
from shadow.platforms.base import BasePlatform, PlatformError, ProgramInfo, ProgramScope, HacktivityEntry


class HackerOneAPI(BasePlatform):
    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, api_key: str = None, username: str = None):
        super().__init__(api_key)
        self.username = username

    def sync_program(self, slug: str) -> ProgramInfo:
        self._require_api_key()
        # Get program info
        resp = self._get(f"/hackers/programs/{slug}")
        data = resp.get("data", {})
        attrs = data.get("attributes", {})

        # Get structured scopes from dedicated endpoint
        scope = ProgramScope()
        try:
            scopes_resp = self._get(f"/hackers/programs/{slug}/structured_scopes",
                                    params={"page[size]": 100})
            for item in scopes_resp.get("data", []):
                s_attrs = item.get("attributes", {})
                asset = s_attrs.get("asset_identifier", "")
                eligible = s_attrs.get("eligible_for_submission", True)
                if not asset:
                    continue
                if not eligible:
                    scope.excluded.append(asset)
                elif asset.startswith("*."):
                    scope.wildcards.append(asset)
                    scope.domains.append(asset[2:])
                else:
                    scope.domains.append(asset)
        except Exception:
            pass

        return ProgramInfo(
            slug=slug,
            name=attrs.get("name", slug),
            platform="hackerone",
            scope=scope,
            submission_state=attrs.get("submission_state", "open"),
            url=f"https://hackerone.com/{slug}",
        )

    def list_programs(self) -> list[ProgramInfo]:
        self._require_api_key()
        resp = self._get("/hackers/programs", params={"page[size]": 25})
        programs = []
        for item in resp.get("data", []):
            attrs = item.get("attributes", {})
            programs.append(ProgramInfo(
                slug=attrs.get("handle", ""),
                name=attrs.get("name", ""),
                platform="hackerone",
                submission_state=attrs.get("submission_state", "open"),
                url=f"https://hackerone.com/{attrs.get('handle', '')}",
            ))
        return programs

    def get_hacktivity(self, slug: str, limit: int = 20) -> list[HacktivityEntry]:
        params = {"page[size]": limit}
        if slug:
            params["queryString"] = f"disclosed:true AND team:{slug}"
        else:
            params["queryString"] = "disclosed:true"
        resp = self._get("/hackers/hacktivity", params=params)
        entries = []
        for item in resp.get("data", []):
            attrs = item.get("attributes", {})
            rels = item.get("relationships", {})
            # Get program from relationships
            prog_attrs = rels.get("program", {}).get("data", {}).get("attributes", {})
            program_handle = prog_attrs.get("handle", slug)
            # Get vuln type from cwe field
            vuln_type = attrs.get("cwe") or "unknown"
            entries.append(HacktivityEntry(
                title=attrs.get("title", ""),
                url=attrs.get("url", ""),
                severity=attrs.get("severity_rating") or "unknown",
                vuln_type=vuln_type,
                bounty=attrs.get("total_awarded_amount"),
                disclosed_at=attrs.get("disclosed_at", ""),
                program=program_handle,
            ))
        return entries

    def search_hacktivity(self, finding) -> Optional[HacktivityEntry]:
        try:
            entries = self.get_hacktivity("", limit=50)
            vuln_lower = finding.vuln_class.lower()
            for entry in entries:
                type_normalized = entry.vuln_type.lower().replace(" ", "")
                title_normalized = entry.title.lower().replace(" ", "")
                if (vuln_lower in entry.vuln_type.lower()
                        or vuln_lower in entry.title.lower()
                        or vuln_lower in type_normalized
                        or vuln_lower in title_normalized):
                    return entry
        except Exception:
            pass
        return None

    def _parse_scope(self, data: dict) -> ProgramScope:
        scope = ProgramScope()
        relationships = data.get("relationships", {})
        structured_scopes = relationships.get("structured_scopes", {}).get("data", [])
        for s in structured_scopes:
            attrs = s.get("attributes", {})
            asset = attrs.get("asset_identifier", "")
            eligible = attrs.get("eligible_for_submission", True)
            if not eligible:
                scope.excluded.append(asset)
            elif asset.startswith("*."):
                scope.wildcards.append(asset)
                scope.domains.append(asset[2:])
            else:
                scope.domains.append(asset)
        return scope

    def _get(self, path: str, params: dict = None) -> dict:
        url = self.BASE_URL + path
        headers = {}
        if self.api_key and self.username:
            creds = base64.b64encode(f"{self.username}:{self.api_key}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
        try:
            resp = httpx.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise PlatformError(f"HackerOne API error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise PlatformError(f"HackerOne request failed: {e}")
