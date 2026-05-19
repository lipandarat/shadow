# /shadow-validate — Validate Finding

Runs the 9-question validation gate on a finding.

**Usage:** `/shadow-validate <finding_id>`
**Example:** `/shadow-validate F001`

**The 9 questions:**
1. Reproducible? (has reproduction steps)
2. In-scope? (domain in scope.yaml)
3. Has concrete evidence? (request/response/screenshot/PoC/OOB hit)
4. Severity realistic? (not inflated)
5. Not a known false positive?
6. Not a duplicate? (fingerprint check)
7. Real impact? (not informational)
8. Exploitable concretely? (not just theory)
9. Not AI hallucination? (no theoretical language without evidence)

**Prompt:**
Run `shadow validate <finding_id>`. Show the result of each of the 9 questions with PASS/FAIL status. If any question fails:
- Explain exactly why it failed
- Tell the user what evidence or information is needed to pass
- Do NOT suggest saving the finding until all 9 questions pass
