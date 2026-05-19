# /shadow-learn — Record Platform Response

Records the platform's response to a submitted finding for future learning.

**Usage:** `/shadow-learn <finding_id> <status> [--bounty <amount>] [--vuln-type <type>]`
**Example:** `/shadow-learn F001 accepted --bounty 500 --vuln-type sqli`

**Status values:**
- `accepted` — finding was accepted and rewarded
- `duplicate` — finding was a duplicate of an existing report
- `informational` — finding was informational, no bounty
- `not_applicable` — finding was out of scope or not applicable

**What it does:**
1. Records the outcome in `brain.md`
2. Updates patterns: which vuln classes are accepted in this program
3. Future hunts will prioritize high-acceptance vuln classes

**Prompt:**
Run `shadow learn <finding_id> <status>` (add `--bounty` and `--vuln-type` if applicable). Then show:
- What was recorded
- Updated statistics (total submitted, accepted, duplicates, total bounty)
- Top priority vuln classes for this program based on acceptance history
