# /hunt — Run Vulnerability Hunt

Runs a full vulnerability hunting cycle against a target.

**Usage:** `/hunt <target> [--vuln-class sqli|xss|ssrf|ssti|lfi|rce|idor]`
**Example:** `/hunt https://example.com --vuln-class sqli`

**What it does:**
1. Scope check — stops if target is out of scope
2. Recon — discovers endpoints
3. Fingerprints target (framework, DB, WAF)
4. Generates adaptive payloads
5. Probes with available tools
6. Validates every finding through 9-question gate
7. Saves only validated findings

**Important:** Only tests in-scope targets. All findings require concrete evidence.

**Prompt:**
Act as a professional pentester. Run `shadow hunt <target>`. For each potential finding, verify it is exploitable with concrete evidence before saving. Never save theoretical findings.
