# /oob — Manage OOB Listener

Manages the Out-of-Band detection listener for blind vulnerabilities.

**Usage:** `/oob start|stop|check`

**What it does:**
- `start`: Starts interactsh-client or local HTTP listener
- `stop`: Stops the listener
- `check`: Shows recent OOB hits

**Prompt:**
Run `shadow oob <action>`. For blind vulnerabilities (blind SQLi, SSRF, XXE), use OOB canary URLs as evidence.
