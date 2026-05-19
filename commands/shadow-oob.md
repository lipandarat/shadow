# /shadow-oob — Manage OOB Listener

Manages the Out-of-Band detection listener for blind vulnerabilities (blind SQLi, SSRF, XXE, CMDi).

**Usage:** `/shadow-oob start|stop|check`

**What it does:**
- `start`: Starts interactsh-client (if available) or local HTTP listener on random port
- `stop`: Stops the active listener
- `check`: Shows recent OOB hits with finding correlation

**When to use OOB:**
- Blind SQL injection (time-based not reliable enough)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) injection
- Blind Command Injection
- Any vulnerability where the response doesn't directly show exploitation

**OOB hit = concrete evidence:** A DNS or HTTP callback to your canary URL proves the vulnerability is real and exploitable. This satisfies questions 3 and 8 of the validation gate.

**Prompt:**
Run `shadow oob <action>`. For `check`:
- Show all recent hits with timestamp, type (DNS/HTTP), and remote IP
- Map each hit to its finding ID
- If a hit is found for a pending finding, remind the user to update the finding's `oob_hit` field and re-run `/shadow-validate`

For `start`: Show the canary domain/URL format to use in payloads.
