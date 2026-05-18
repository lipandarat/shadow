# /learn — Record Platform Response

Records the platform's response to a submitted finding for future learning.

**Usage:** `/learn <finding_id> <status> [--bounty <amount>] [--vuln-type <type>]`
**Example:** `/learn F001 accepted --bounty 500 --vuln-type sqli`

**Status values:** accepted, duplicate, informational, not_applicable

**Prompt:**
Run `shadow learn <finding_id> <status>`. Update brain.md with the learning. Show updated statistics.
