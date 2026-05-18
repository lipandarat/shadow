# /chain — Build Exploit Chain

Builds an exploit chain from related findings that share the same target domain.

**Usage:** `/chain <finding_id>`
**Example:** `/chain F001`

**What it does:**
1. Finds all other validated findings on the same target domain
2. Sorts findings by exploit order (recon → info → auth → injection → RCE)
3. Calculates combined CVSS score (higher than individual findings)
4. Creates a new chain finding with all steps

**Prompt:**
Run `shadow chain <finding_id>`. Show the exploit chain in order of exploitation steps with:
- Step number and finding ID
- Vuln class and severity for each step
- Combined CVSS score
- Narrative explanation of how the chain works end-to-end

If only one finding exists, explain that a chain requires multiple related findings on the same domain.
