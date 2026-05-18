"""Tests for platform factory."""

import pytest
from shadow.platforms.factory import get_platform, SUPPORTED_PLATFORMS
from shadow.platforms.hackerone import HackerOneAPI
from shadow.platforms.bugcrowd import BugcrowdAPI
from shadow.platforms.base import BasePlatform


class TestPlatformFactory:
    def test_get_hackerone_returns_correct_class(self):
        client = get_platform("hackerone", api_key="test")
        assert isinstance(client, HackerOneAPI)
        assert isinstance(client, BasePlatform)

    def test_get_bugcrowd_returns_correct_class(self):
        client = get_platform("bugcrowd", api_key="test")
        assert isinstance(client, BugcrowdAPI)
        assert isinstance(client, BasePlatform)

    def test_case_insensitive(self):
        client = get_platform("HackerOne", api_key="test")
        assert isinstance(client, HackerOneAPI)

    def test_unknown_platform_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown platform"):
            get_platform("unknown_platform")

    def test_api_key_passed_to_client(self):
        client = get_platform("hackerone", api_key="my-secret-key")
        assert client.api_key == "my-secret-key"

    def test_supported_platforms_list(self):
        assert "hackerone" in SUPPORTED_PLATFORMS
        assert "bugcrowd" in SUPPORTED_PLATFORMS
        assert len(SUPPORTED_PLATFORMS) == 2
