# /shadow-sync — Sync Scope from Platform

Syncs program scope, policy, and hacktivity from a bug bounty platform.

**Usage:** `/shadow-sync <platform> <program>`
**Example:** `/shadow-sync hackerone tesla`

**What it does:**
1. Fetches scope (domains, wildcards, exclusions) via platform API
2. Updates `scope.yaml` in the engagement workspace
3. Fetches recent hacktivity for context
4. Updates `brain.md` with scope summary

**Requires:** API key configured in `~/.shadow/config.yaml`

**Prompt:**
Run `shadow sync <platform> <program>`. If the command fails with an API key error, show the user exactly what to add to `~/.shadow/config.yaml`:

```yaml
platforms:
  hackerone:
    api_key: "YOUR_KEY_HERE"
    username: "YOUR_USERNAME"
  bugcrowd:
    api_key: "YOUR_KEY_HERE"
```

After sync, show the in-scope domains that were fetched.
