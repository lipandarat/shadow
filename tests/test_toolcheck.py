import shutil
import pytest
from unittest.mock import patch
from shadow.core.toolcheck import ToolChecker, ToolInfo, TOOLS


class TestToolChecker:
    def test_check_all_returns_all_tools(self):
        checker = ToolChecker()
        result = checker.check_all()
        assert set(result.keys()) == set(TOOLS.keys())

    def test_tool_info_has_required_fields(self):
        checker = ToolChecker()
        result = checker.check_all()
        for name, info in result.items():
            assert isinstance(info, ToolInfo)
            assert info.name == name
            assert isinstance(info.available, bool)
            assert isinstance(info.description, str)

    def test_python_not_in_tools(self):
        # python is not a security tool — should not be in TOOLS
        assert "python" not in TOOLS

    def test_detects_available_tool(self):
        checker = ToolChecker()
        # Mock shutil.which to return a path for nmap
        with patch("shutil.which", side_effect=lambda t: "/usr/bin/nmap" if t == "nmap" else None):
            checker.invalidate_cache()
            assert checker.is_available("nmap")
            assert checker.get_path("nmap") == "/usr/bin/nmap"

    def test_detects_unavailable_tool(self):
        checker = ToolChecker()
        with patch("shutil.which", return_value=None):
            checker.invalidate_cache()
            assert not checker.is_available("nuclei")
            assert checker.get_path("nuclei") is None

    def test_available_tools_returns_bool_dict(self):
        checker = ToolChecker()
        result = checker.available_tools()
        assert isinstance(result, dict)
        assert all(isinstance(v, bool) for v in result.values())

    def test_results_are_cached(self):
        checker = ToolChecker()
        with patch("shutil.which", return_value=None) as mock_which:
            checker.check_all()
            checker.check_all()  # second call should use cache
        # shutil.which should only be called once per tool (not twice)
        assert mock_which.call_count == len(TOOLS)

    def test_invalidate_cache_forces_recheck(self):
        checker = ToolChecker()
        with patch("shutil.which", return_value=None):
            checker.check_all()
        checker.invalidate_cache()
        with patch("shutil.which", return_value="/usr/bin/nmap") as mock_which:
            checker.check_all()
        assert mock_which.call_count == len(TOOLS)

    def test_summary_contains_tool_names(self):
        checker = ToolChecker()
        with patch("shutil.which", return_value=None):
            checker.invalidate_cache()
            summary = checker.summary()
        assert "nmap" in summary
        assert "nuclei" in summary
        assert "ffuf" in summary

    def test_tools_dict_has_10_entries(self):
        assert len(TOOLS) == 10
