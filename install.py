#!/usr/bin/env python3
"""Shadow installer — install/verify/render/uninstall for Claude Code integration."""

import argparse
import json
import os
import shutil
import subprocess
import sys


CLAUDE_SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
CLAUDE_COMMANDS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "commands")
SHADOW_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".shadow")
SHADOW_CONFIG_PATH = os.path.join(SHADOW_CONFIG_DIR, "config.yaml")
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
COMMANDS_SRC_DIR = os.path.join(PROJECT_ROOT, "commands")

MCP_SERVERS = {
    "bounty-platforms": {
        "command": sys.executable,
        "args": ["-m", "shadow.cli.main", "mcp", "serve", "bounty-platforms"],
        "cwd": PROJECT_ROOT,
    },
    "writeup-search": {
        "command": sys.executable,
        "args": ["-m", "shadow.cli.main", "mcp", "serve", "writeup-search"],
        "cwd": PROJECT_ROOT,
    },
}

HOOKS = {
    "PreToolUse": [
        {
            "matcher": "Write|Edit",
            "hooks": [{
                "type": "command",
                "command": f'"{sys.executable}" -m shadow.hooks.pre_save_check',
            }],
        },
        {
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": f'"{sys.executable}" -m shadow.hooks.scope_check',
            }],
        },
    ]
}

SHADOW_CONFIG_TEMPLATE = """# Shadow configuration
platforms:
  hackerone:
    api_key: ""
    username: ""
  bugcrowd:
    api_key: ""

oob:
  mode: interactsh  # interactsh or selfhosted
  selfhosted_port: 0

opsec:
  delay_range: [1.0, 3.0]
  max_requests_per_minute: 30
"""


def cmd_install(args):
    print("Installing Shadow...")

    # 1. pip install -e .
    print("  [1/6] Installing Python package...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", ".", "--quiet"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  ERROR: pip install failed:\n{result.stderr}")
        sys.exit(1)
    print("       OK")

    # 2. Write MCP entries to Claude settings
    print("  [2/6] Registering MCP servers...")
    _write_mcp_settings()
    print("       OK")

    # 3. Write hooks to Claude settings
    print("  [3/6] Installing Claude Code hooks...")
    _write_hooks_settings()
    print("       OK")

    # 4. Copy slash commands
    print("  [4/6] Installing slash commands...")
    _copy_slash_commands()
    print("       OK")

    # 5. Create ~/.shadow/config.yaml
    print("  [5/6] Creating Shadow config...")
    _create_shadow_config()
    print("       OK")

    # 6. Run verify
    print("  [6/6] Verifying installation...")
    success = _run_verify(quiet=False)
    if success:
        print("\nInstallation complete.")
        print(f"Config: {SHADOW_CONFIG_PATH}")
        print("Set your API keys in the config file to enable platform sync.")
    else:
        print("\nInstallation completed with warnings. Run 'python install.py verify' for details.")


def cmd_verify(args):
    success = _run_verify(quiet=False)
    sys.exit(0 if success else 1)


def cmd_render(args):
    print("=== Shadow Configuration ===\n")

    settings = _load_claude_settings()

    print("MCP Servers:")
    mcp = settings.get("mcpServers", {})
    if mcp:
        for name, cfg in mcp.items():
            print(f"  {name}: {cfg.get('command')} {' '.join(cfg.get('args', []))}")
    else:
        print("  (none registered)")

    print("\nHooks:")
    hooks = settings.get("hooks", {})
    if hooks:
        for event, hook_list in hooks.items():
            print(f"  {event}:")
            for h in hook_list:
                print(f"    matcher={h.get('matcher')} -> {h.get('hooks', [{}])[0].get('command', '')}")
    else:
        print("  (none registered)")

    print("\nSlash Commands:")
    if os.path.isdir(CLAUDE_COMMANDS_DIR):
        cmds = [f for f in os.listdir(CLAUDE_COMMANDS_DIR) if f.endswith(".md")]
        if cmds:
            for cmd in sorted(cmds):
                print(f"  /{cmd[:-3]}")
        else:
            print("  (none installed)")
    else:
        print("  (commands dir not found)")

    print(f"\nShadow Config: {SHADOW_CONFIG_PATH}")
    if os.path.exists(SHADOW_CONFIG_PATH):
        print("  (exists)")
    else:
        print("  (not found)")

    print("\nCLAUDE.md:")
    claude_md_path = os.path.join(os.path.expanduser("~"), ".claude", "CLAUDE.md")
    if os.path.exists(claude_md_path):
        print(f"  {claude_md_path} (exists)")
    else:
        print(f"  {claude_md_path} (not installed)")

    print(f"\nShadow Version: 0.1.0")


def cmd_uninstall(args):
    print("Uninstalling Shadow...")

    # 1. Remove MCP entries
    print("  [1/4] Removing MCP servers...")
    settings = _load_claude_settings()
    mcp = settings.get("mcpServers", {})
    for name in list(MCP_SERVERS.keys()):
        mcp.pop(name, None)
    settings["mcpServers"] = mcp
    _save_claude_settings(settings)
    print("       OK")

    # 2. Remove hooks
    print("  [2/4] Removing hooks...")
    settings = _load_claude_settings()
    settings.pop("hooks", None)
    _save_claude_settings(settings)
    print("       OK")

    # 3. Remove slash commands
    print("  [3/4] Removing slash commands...")
    if os.path.isdir(COMMANDS_SRC_DIR) and os.path.isdir(CLAUDE_COMMANDS_DIR):
        for fname in os.listdir(COMMANDS_SRC_DIR):
            target = os.path.join(CLAUDE_COMMANDS_DIR, fname)
            if os.path.exists(target):
                os.remove(target)
    print("       OK")

    # 4. pip uninstall
    print("  [4/4] Uninstalling Python package...")
    subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "shadow", "-y", "--quiet"],
        capture_output=True
    )
    print("       OK")

    print("\nUninstall complete.")
    print(f"Note: Engagement data in {SHADOW_CONFIG_DIR} was NOT deleted.")
    print(f"To delete all data: rm -rf {SHADOW_CONFIG_DIR}")


def _run_verify(quiet=False) -> bool:
    checks = []

    # Check 1: Python imports
    try:
        import shadow
        import shadow.core.models
        import shadow.core.store
        import shadow.core.validate
        import shadow.core.scope
        import shadow.core.audit
        import shadow.core.engagement
        import shadow.core.cvss
        import shadow.core.dedup
        import shadow.core.opsec
        import shadow.core.session
        import shadow.core.toolcheck
        import shadow.core.brain
        import shadow.core.learn
        import shadow.agents.recon
        import shadow.agents.hunt
        import shadow.agents.validate
        import shadow.agents.chain
        import shadow.agents.report
        import shadow.agents.dupcheck
        import shadow.agents.learn
        import shadow.mcp.server
        import shadow.mcp.bounty_platforms
        import shadow.mcp.writeup_search
        import shadow.platforms.base
        import shadow.platforms.hackerone
        import shadow.platforms.bugcrowd
        import shadow.platforms.factory
        import shadow.hooks.pre_save_check
        import shadow.hooks.scope_check
        checks.append(("Python package imports", True, ""))
    except ImportError as e:
        checks.append(("Python package imports", False, str(e)))

    # Check 2: MCP entries in settings
    settings = _load_claude_settings()
    mcp = settings.get("mcpServers", {})
    for name in MCP_SERVERS:
        ok = name in mcp
        checks.append((f"MCP server: {name}", ok, "" if ok else "Not registered"))

    # Check 3: Hooks in settings
    hooks = settings.get("hooks", {})
    ok = bool(hooks.get("PreToolUse"))
    checks.append(("Claude Code hooks", ok, "" if ok else "Not installed"))

    # Check 4: Slash commands
    if os.path.isdir(CLAUDE_COMMANDS_DIR):
        cmds = os.listdir(CLAUDE_COMMANDS_DIR)
        ok = any(f.endswith(".md") for f in cmds)
        checks.append(("Slash commands", ok, "" if ok else "No .md files found"))
    else:
        checks.append(("Slash commands", False, "Commands dir not found"))

    # Check 5: MCP dry-run
    try:
        result = subprocess.run(
            [sys.executable, "-m", "shadow.cli.main", "mcp", "serve", "bounty-platforms", "--dry-run"],
            capture_output=True, text=True, timeout=10
        )
        ok = result.returncode == 0 and "Dry run: OK" in result.stdout
        checks.append(("MCP dry-run", ok, result.stderr if not ok else ""))
    except Exception as e:
        checks.append(("MCP dry-run", False, str(e)))

    # Check 6: Bundle test
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_mcp_bundle.py", "-v", "--tb=short", "-q"],
            capture_output=True, text=True, timeout=30
        )
        ok = result.returncode == 0
        checks.append(("MCP bundle test", ok, result.stdout[-200:] if not ok else ""))
    except Exception as e:
        checks.append(("MCP bundle test", False, str(e)))

    all_pass = all(ok for _, ok, _ in checks)

    if not quiet:
        print("\n=== Verification Results ===")
        for name, ok, msg in checks:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name}")
            if not ok and msg:
                print(f"         {msg}")
        print(f"\nOverall: {'PASS' if all_pass else 'FAIL'}")

    return all_pass


def _write_mcp_settings():
    """Register MCP servers using claude mcp add command (correct way for Claude Code)."""
    shadow_dir = PROJECT_ROOT

    for name, cfg in MCP_SERVERS.items():
        # Remove existing server first (ignore errors if not exists)
        subprocess.run(
            ["claude", "mcp", "remove", name],
            capture_output=True, text=True
        )
        # Add server using claude mcp add
        cmd = [
            "claude", "mcp", "add",
            "--transport", "stdio",
            "--scope", "user",
            name, "--",
            cfg["command"],
        ] + cfg["args"]

        result = subprocess.run(cmd, capture_output=True, text=True, cwd=shadow_dir)
        if result.returncode != 0:
            # Fallback: write directly to settings.json
            settings = _load_claude_settings()
            if "mcpServers" not in settings:
                settings["mcpServers"] = {}
            settings["mcpServers"][name] = cfg
            _save_claude_settings(settings)


def _write_hooks_settings():
    settings = _load_claude_settings()
    settings["hooks"] = HOOKS
    _save_claude_settings(settings)


def _copy_slash_commands():
    os.makedirs(CLAUDE_COMMANDS_DIR, exist_ok=True)
    if os.path.isdir(COMMANDS_SRC_DIR):
        for fname in os.listdir(COMMANDS_SRC_DIR):
            if fname.endswith(".md"):
                shutil.copy2(
                    os.path.join(COMMANDS_SRC_DIR, fname),
                    os.path.join(CLAUDE_COMMANDS_DIR, fname)
                )

    # Merge claude/CLAUDE.md → ~/.claude/CLAUDE.md
    # If file doesn't exist: copy directly
    # If file exists but Shadow block not present: append Shadow block
    # If Shadow block already present: skip (already merged)
    claude_md_src = os.path.join(PROJECT_ROOT, "claude", "CLAUDE.md")
    claude_md_dst = os.path.join(os.path.expanduser("~"), ".claude", "CLAUDE.md")
    SHADOW_BLOCK_MARKER = "<!-- shadow-assistant managed block -->"

    if os.path.isfile(claude_md_src):
        with open(claude_md_src, encoding="utf-8") as f:
            shadow_content = f.read()

        if not os.path.exists(claude_md_dst):
            # File doesn't exist — write directly
            with open(claude_md_dst, "w", encoding="utf-8") as f:
                f.write(SHADOW_BLOCK_MARKER + "\n")
                f.write(shadow_content)
        else:
            # File exists — check if Shadow block already present
            with open(claude_md_dst, encoding="utf-8") as f:
                existing = f.read()
            if SHADOW_BLOCK_MARKER not in existing:
                # Append Shadow block
                with open(claude_md_dst, "a", encoding="utf-8") as f:
                    f.write("\n\n" + SHADOW_BLOCK_MARKER + "\n")
                    f.write(shadow_content)


def _create_shadow_config():
    os.makedirs(SHADOW_CONFIG_DIR, exist_ok=True)
    if not os.path.exists(SHADOW_CONFIG_PATH):
        with open(SHADOW_CONFIG_PATH, "w") as f:
            f.write(SHADOW_CONFIG_TEMPLATE)


def _load_claude_settings() -> dict:
    os.makedirs(os.path.dirname(CLAUDE_SETTINGS_PATH), exist_ok=True)
    if os.path.exists(CLAUDE_SETTINGS_PATH):
        with open(CLAUDE_SETTINGS_PATH) as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def _save_claude_settings(settings: dict):
    os.makedirs(os.path.dirname(CLAUDE_SETTINGS_PATH), exist_ok=True)
    with open(CLAUDE_SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Shadow installer for Claude Code integration",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.add_parser("install", help="Install Shadow and configure Claude Code")
    subparsers.add_parser("verify", help="Verify installation")
    subparsers.add_parser("render", help="Show current configuration")
    subparsers.add_parser("uninstall", help="Remove Shadow from Claude Code")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "render":
        cmd_render(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
