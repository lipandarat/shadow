# /report — Generate Report

Generates a bug bounty report draft. NEVER auto-submits.

**Usage:** `/report [--format md|yaml]`

**What it does:**
1. Loads all validated/reported/accepted findings (skips drafts)
2. Checks for duplicates against platform hacktivity
3. Calculates CVSS scores for each finding
4. Generates Markdown report with: summary table, per-finding sections, evidence, reproduction steps, fix recommendations
5. Saves draft to `~/.shadow/engagements/<engagement>/report.md`

**Important:** NEVER submit automatically. Always show the draft first.

**Prompt:**
Run `shadow report`. Then:
1. Show the path to the generated report file
2. Display the full report content for review
3. Ask the user: "Please review this report. Do you want to make any changes before submitting?"
4. Wait for explicit user confirmation before any submission action
5. NEVER submit to any platform without explicit user approval
