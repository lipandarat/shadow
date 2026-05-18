# /report — Generate Report

Generates a bug bounty report draft. NEVER auto-submits.

**Usage:** `/report`

**What it does:**
1. Loads all validated findings
2. Checks for duplicates
3. Generates Markdown report with CVSS scores
4. Shows draft for review

**Important:** Always show the draft to the user before any submission. Never submit automatically.

**Prompt:**
Run `shadow report`. Show the generated report draft. Ask the user to review before any submission.
