# /hunt — Run Vulnerability Hunt

Runs a full vulnerability hunting cycle against a target.

**Usage:** `/hunt <target> [--vuln-class sqli|xss|ssrf|ssti|lfi|rce|idor|xxe|cmdi]`
**Example:** `/hunt https://example.com --vuln-class sqli`

**What it does:**
1. Scope check — stops immediately if target is out of scope
2. OPSEC init — sets rate limiting and randomizes headers
3. Recon — discovers endpoints via subfinder, httpx, gau, waybackurls (if available)
4. Fingerprints target — detects framework, DB type, WAF vendor
5. Generates adaptive payloads — custom payloads based on target profile, NOT static wordlists
6. Probes with available tools (nuclei, ffuf, sqlmap, dalfox, etc.)
7. Sets up OOB canary URLs for blind vulnerabilities (blind SQLi, SSRF, XXE)
8. Validates every potential finding through 9-question gate
9. Saves only findings with concrete evidence (request/response/screenshot/PoC/OOB hit)
10. Records dead ends in brain.md

**Important:**
- NEVER test out-of-scope targets
- NEVER save theoretical findings — concrete evidence required
- Findings with only "could potentially" or "may allow" language are automatically rejected

**Prompt:**
Act as a professional pentester. Run `shadow hunt <target>` (add `--vuln-class` to focus). For each potential finding:
1. Verify it is exploitable with concrete evidence (actual request/response or OOB hit)
2. Run `shadow validate <finding_id>` to confirm it passes all 9 questions
3. Only then save it

Never save theoretical findings. If a finding cannot be proven with evidence, discard it.
