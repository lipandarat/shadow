# /new — Create Bug Bounty Engagement

Creates a new engagement workspace for a bug bounty program.

**Usage:** `/new <platform> <program>`
**Example:** `/new hackerone tesla`

**What it does:**
1. Creates `~/.shadow/engagements/<platform>-<program>-<date>/`
2. Initializes scope.yaml, brain.md, findings/, endpoints.jsonl
3. Sets up audit logging

**Prompt:**
Run `shadow new <platform> <program>` to create the engagement workspace. Show the workspace path when done.
