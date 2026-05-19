"""Integration tests for install.py."""

import os
import subprocess
import sys

import install


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

    def test_render_shows_claude_md_status(self):
        """render should show CLAUDE.md status."""
        result = subprocess.run(
            [sys.executable, "install.py", "render"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.expanduser("~"), "shadow")
        )
        assert result.returncode == 0
        assert "CLAUDE" in result.stdout

    def test_verify_exits_with_code(self):
        result = subprocess.run(
            [sys.executable, "install.py", "verify"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.expanduser("~"), "shadow")
        )
        # Exit code 0 or 1 — both are valid (depends on whether installed)
        assert result.returncode in (0, 1)
        assert "Verification Results" in result.stdout

    def test_copy_slash_commands_installs_renamed_command_files(self, monkeypatch, tmp_path):
        commands_dir = tmp_path / ".claude" / "commands"

        monkeypatch.setattr(install, "CLAUDE_COMMANDS_DIR", str(commands_dir))
        monkeypatch.setattr(install, "os", install.os)
        monkeypatch.setattr(install.os.path, "expanduser", lambda _: str(tmp_path))

        install._copy_slash_commands()

        assert (commands_dir / "shadow-new.md").exists()
        assert any(path.name.startswith("shadow-") for path in commands_dir.glob("*.md"))
