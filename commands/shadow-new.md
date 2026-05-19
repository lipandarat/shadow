# /shadow-new — Create Bug Bounty Engagement

Creates a new engagement workspace for a bug bounty program.

**Usage:** `/shadow-new <platform> <program>`
**Example:** `/shadow-new hackerone tesla`

**What it does:**
1. Creates `~/.shadow/engagements/<platform>-<program>-<date>/`
2. Initializes: `scope.yaml`, `brain.md`, `findings/`, `endpoints.jsonl`, `events.jsonl`, `session.jsonl`
3. Sets up audit logging

**Prompt:**
Run `shadow new <platform> <program>` to create the engagement workspace. Show the workspace path and list all files created when done. Then remind the user to run `/shadow-sync <platform> <program>` to fetch scope from the platform.
