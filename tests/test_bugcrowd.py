"""Tests for BugcrowdAPI."""

import pytest
from unittest.mock import patch, MagicMock
from shadow.platforms.bugcrowd import BugcrowdAPI
from shadow.platforms.base import PlatformError, ProgramInfo, HacktivityEntry


def mock_response(data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    return resp


class TestBugcrowdAPI:
    @pytest.fixture
    def api(self):
        return BugcrowdAPI(api_key="test-key")

    def test_sync_program_returns_program_info(self, api):
        data = {"program": {"name": "Tesla", "program_state": "open", "targets": {"in_scope": [], "out_of_scope": []}}}
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.sync_program("tesla")
        assert isinstance(result, ProgramInfo)
        assert result.slug == "tesla"
        assert result.platform == "bugcrowd"

    def test_sync_program_parses_scope(self, api):
        data = {
            "program": {
                "name": "Tesla",
                "program_state": "open",
                "targets": {
                    "in_scope": [{"target": "*.tesla.com"}, {"target": "tesla.com"}],
                    "out_of_scope": [{"target": "admin.tesla.com"}],
                },
            }
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.sync_program("tesla")
        assert "tesla.com" in result.scope.domains
        assert "admin.tesla.com" in result.scope.excluded

    def test_list_programs_returns_list(self, api):
        data = {
            "programs": [
                {"code": "tesla", "name": "Tesla", "program_state": "open"},
                {"code": "uber", "name": "Uber", "program_state": "open"},
            ]
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.list_programs()
        assert len(result) == 2
        assert result[0].slug == "tesla"

    def test_get_hacktivity_returns_entries(self, api):
        data = {
            "disclosures": [
                {
                    "title": "XSS in search",
                    "url": "https://bugcrowd.com/disclosures/123",
                    "severity": "medium",
                    "paid_amount": 300,
                    "disclosed_at": "2024-01-01",
                }
            ]
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.get_hacktivity("tesla")
        assert len(result) == 1
        assert result[0].title == "XSS in search"
        assert result[0].bounty == 300

    def test_requires_api_key_for_sync(self):
        api = BugcrowdAPI()
        with pytest.raises(PlatformError, match="API key"):
            api.sync_program("tesla")

    def test_api_error_raises_platform_error(self, api):
        with patch("httpx.get", return_value=mock_response({}, status_code=404)):
            with pytest.raises(PlatformError):
                api.sync_program("nonexistent")

    def test_search_hacktivity_returns_none_on_empty(self, api):
        from shadow.core.models import Finding
        finding = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        with patch("httpx.get", return_value=mock_response({"disclosures": []})):
            result = api.search_hacktivity(finding)
        assert result is None
