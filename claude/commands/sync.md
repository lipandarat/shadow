# /sync — Sync Scope from Platform

Syncs program scope, policy, and hacktivity from a bug bounty platform.

**Usage:** `/sync <platform> <program>`
**Example:** `/sync hackerone tesla`

**What it does:**
1. Fetches scope (domains, wildcards, exclusions) via platform API
2. Updates scope.yaml in the engagement workspace
3. Fetches recent hacktivity for context

**Prompt:**
Run `shadow sync <platform> <program>`. If API key is not configured, remind the user to set it in `~/.shadow/config.yaml` under `platforms.<platform>.api_key`.
