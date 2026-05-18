"""Tests for HackerOneAPI — uses httpx mocking."""

import pytest
from unittest.mock import patch, MagicMock
from shadow.platforms.hackerone import HackerOneAPI
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


class TestHackerOneAPI:
    @pytest.fixture
    def api(self):
        return HackerOneAPI(api_key="test-key", username="test-user")

    def test_sync_program_returns_program_info(self, api):
        data = {
            "data": {
                "attributes": {"name": "Tesla", "submission_state": "open"},
                "relationships": {"structured_scopes": {"data": []}},
            }
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.sync_program("tesla")
        assert isinstance(result, ProgramInfo)
        assert result.slug == "tesla"
        assert result.name == "Tesla"
        assert result.platform == "hackerone"

    def test_sync_program_parses_scope(self, api):
        data = {
            "data": {
                "attributes": {"name": "Tesla", "submission_state": "open"},
                "relationships": {
                    "structured_scopes": {
                        "data": [
                            {"attributes": {"asset_identifier": "*.tesla.com", "eligible_for_submission": True}},
                            {"attributes": {"asset_identifier": "admin.tesla.com", "eligible_for_submission": False}},
                        ]
                    }
                },
            }
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.sync_program("tesla")
        assert "tesla.com" in result.scope.domains
        assert "admin.tesla.com" in result.scope.excluded

    def test_list_programs_returns_list(self, api):
        data = {
            "data": [
                {"attributes": {"handle": "tesla", "name": "Tesla", "submission_state": "open"}},
                {"attributes": {"handle": "uber", "name": "Uber", "submission_state": "open"}},
            ]
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.list_programs()
        assert len(result) == 2
        assert result[0].slug == "tesla"

    def test_get_hacktivity_returns_entries(self, api):
        data = {
            "data": [
                {
                    "attributes": {
                        "title": "SQL Injection",
                        "url": "https://hackerone.com/reports/123",
                        "severity_rating": "high",
                        "weakness": {"name": "SQL Injection"},
                        "total_awarded_amount": 500,
                        "disclosed_at": "2024-01-01",
                    }
                }
            ]
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.get_hacktivity("tesla")
        assert len(result) == 1
        assert result[0].title == "SQL Injection"
        assert result[0].bounty == 500

    def test_requires_api_key_for_sync(self):
        api = HackerOneAPI()
        with pytest.raises(PlatformError, match="API key"):
            api.sync_program("tesla")

    def test_api_error_raises_platform_error(self, api):
        with patch("httpx.get", return_value=mock_response({}, status_code=404)):
            with pytest.raises(PlatformError):
                api.sync_program("nonexistent")

    def test_search_hacktivity_returns_match(self, api):
        from shadow.core.models import Finding
        finding = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        data = {
            "data": [
                {
                    "attributes": {
                        "title": "SQL Injection in login",
                        "url": "https://hackerone.com/reports/999",
                        "severity_rating": "high",
                        "weakness": {"name": "SQL Injection"},
                        "total_awarded_amount": 1000,
                        "disclosed_at": "2024-01-01",
                    }
                }
            ]
        }
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.search_hacktivity(finding)
        assert result is not None

    def test_search_hacktivity_returns_none_on_no_match(self, api):
        from shadow.core.models import Finding
        finding = Finding(title="XSS", vuln_class="xss", target="https://x.com")
        data = {"data": []}
        with patch("httpx.get", return_value=mock_response(data)):
            result = api.search_hacktivity(finding)
        assert result is None
