"""Integration tests for install.py."""

import json
import os
import subprocess
import sys
import tempfile
import pytest


class TestInstaller:
    def test_installer_help(self):
        result = subprocess.run(
            [sys.executable, "install.py", "--help"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.expanduser("~"), "shadow")
        )
        assert result.returncode == 0
        assert "install" in result.stdout
        assert "verify" in result.stdout
        assert "render" in result.stdout
        assert "uninstall" in result.stdout

    def test_render_runs_cleanly(self):
        result = subprocess.run(
            [sys.executable, "install.py", "render"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.expanduser("~"), "shadow")
        )
        assert result.returncode == 0
        assert "Shadow Configuration" in result.stdout

    def test_verify_exits_with_code(self):
        result = subprocess.run(
            [sys.executable, "install.py", "verify"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.expanduser("~"), "shadow")
        )
        # Exit code 0 or 1 — both are valid (depends on whether installed)
        assert result.returncode in (0, 1)
        assert "Verification Results" in result.stdout
