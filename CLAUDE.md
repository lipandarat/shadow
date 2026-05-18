# Shadow — Bug Bounty Assistant

Shadow is a professional bug bounty hunting assistant. Use these commands to manage engagements, hunt vulnerabilities, validate findings, and generate reports.

## MCP Servers

Two MCP servers are available:
- `bounty-platforms`: sync scope, list programs, check scope
- `writeup-search`: search writeups, find similar findings

## Available Commands

| Command | Description |
|---------|-------------|
| `/new <platform> <program>` | Create engagement workspace |
| `/sync <platform> <program>` | Sync scope from platform |
| `/hunt <target> [--vuln-class X]` | Run vulnerability hunt |
| `/validate <finding_id>` | 9-question validation gate |
| `/chain <finding_id>` | Build exploit chain |
| `/report` | Generate draft report |
| `/dupcheck <finding_id>` | Check for duplicates |
| `/learn <id> <status> [--bounty N]` | Record platform response |
| `/oob start\|stop\|check` | Manage OOB listener |

## Validation Gate

Every finding must pass 9 questions before being saved:
1. Reproducible
2. In-scope
3. Has concrete evidence
4. Severity realistic
5. Not known false positive
6. Not duplicate
7. Real impact
8. Exploitable concretely
9. Not AI hallucination

## Important Rules

- NEVER auto-submit reports — always show draft first
- NEVER test out-of-scope targets
- ALWAYS verify findings with concrete evidence before saving
- Theoretical findings without proof are automatically rejected

## MCP Tools

### bounty-platforms

- `sync_program(platform, slug)` — fetch scope + policy, save to scope.yaml
- `list_programs(platform)` — list active programs
- `get_hacktivity(platform, slug)` — recent public reports
- `check_scope(url, engagement_id)` — check if URL is in scope

### writeup-search

- `search_writeups(query, platform)` — search writeups by query
- `get_writeup(url)` — fetch writeup content
- `similar_findings(vuln_type)` — find similar findings by vuln type
