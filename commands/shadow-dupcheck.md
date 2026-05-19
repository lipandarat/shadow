# /shadow-dupcheck — Check Duplicates

Checks if a finding is a duplicate of existing local findings or platform hacktivity.

**Usage:** `/shadow-dupcheck <finding_id>`
**Example:** `/shadow-dupcheck F001`

**What it does:**
1. Computes SHA-256 fingerprint of the finding (target + vuln_class + parameter)
2. Checks against all local findings in `findings/`
3. Checks against platform hacktivity (if API key configured)
4. Returns match details if duplicate found

**Prompt:**
Run `shadow dupcheck <finding_id>`. Show:
- The fingerprint hash
- Whether a local match was found (and which finding ID)
- Whether a platform match was found (and the URL)
- Final verdict: UNIQUE or DUPLICATE

If DUPLICATE: advise the user not to submit this finding.
If UNIQUE: confirm it is safe to proceed with reporting.
