# Shadow Payload Engine + OOB — Implementation Plan 4/8

> **Requires:** Plans 1+2 complete

**Goal:** Adaptive payload engine (target fingerprinting → custom payload generation → feedback loop) and OOB detection infrastructure (interactsh + self-hosted).

---

### Task 1: Target fingerprinter

**Create:** `shadow/payloads/__init__.py`, `shadow/payloads/fingerprint.py`, `tests/test_payload_fingerprint.py`

`TargetFingerprinter` — profiles a target by probing:
- `detect_framework(response) -> str` — Laravel/Django/Spring/Express (header, cookie, error patterns)
- `detect_db(error_messages) -> str` — MySQL/PostgreSQL/MSSQL (error message signatures)
- `detect_waf(response_headers) -> str` — ModSecurity/Cloudflare/AWS WAF (header markers)
- `probe_filtered_chars(target) -> set[str]` — sends probe payloads, checks what gets stripped
- `measure_timing_baseline(target, samples=5) -> float` — average response time in ms
- `profile(target) -> TargetProfile` — aggregates all above into one object

Tests: mock responses for each framework/DB/WAF combo, verify detection

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement fingerprint.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 2: Adaptive payload engine

**Create:** `shadow/payloads/engine.py`, `tests/test_payload_engine.py`

`AdaptivePayloadEngine`:
- `generate(profile: TargetProfile, vuln_class: str) -> list[Payload]`
  - Selects syntax based on `profile.db_type` (MySQL/PostgreSQL/MSSQL-specific payloads)
  - Selects encodings based on `profile.filtered_chars` (URL encode only chars that pass filter)
  - Selects WAF bypasses based on `profile.waf_vendor` (vendor-specific bypass patterns)
- Does NOT use static wordlists — generates payloads programmatically
- `Payload` dataclass: raw string, encoding, target_db, bypass_method

Tests: verify MySQL profile → MySQL-specific payloads, verify filtered chars → appropriate encodings

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement engine.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 3: Payload feedback loop

**Create:** `shadow/payloads/feedback.py`, `tests/test_payload_feedback.py`

`PayloadFeedback(engine)`:
- `analyze_response(payload, response, baseline_timing) -> FeedbackSignal`
  - Detects anomalies: status code change, timing spike (>2x baseline), new error message, response length change (>30%)
  - If anomaly → `engine.generate_variants(payload, anomaly_details)` → more payloads
  - If no anomaly → DISCARD payload
- `generate_variants(payload, anomalies) -> list[Payload]` — mutates successful payloads

Tests: mock responses with anomalies, verify variants generated; mock normal response, verify discarded

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement feedback.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 4: OOB collector interface

**Create:** `shadow/oob/__init__.py`, `shadow/oob/collector.py`, `tests/test_oob.py`

`OOBCollector` (abstract interface):
- `get_canary(finding_id) -> str` — generates unique canary URL
- `check_hit(finding_id) -> OOBHit | None` — checks if canary was triggered
- `start() / stop()` — lifecycle management
- `is_running() -> bool`

`OOBHit` dataclass: timestamp, type (DNS/HTTP), remote_ip, raw_data

Tests: test canary URLs are unique per finding_id, test check_hit returns None when no hit

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement collector.py (abstract base)
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 5: Interactsh integration

**Create:** `shadow/oob/interactsh.py`

`InteractshCollector(OOBCollector)`:
- Uses `shutil.which("interactsh-client")` to detect
- Falls back to subprocess with `interactsh-client -poll 5` if binary available
- Canary format: `shadow-{engagement_id}-{finding_id}.{interactsh_domain}`
- `check_hit(finding_id)` — polls interactsh API, matches by correlation ID

Tests: mock interactsh subprocess output, verify canary parsing

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement interactsh.py
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

### Task 6: Self-hosted OOB (stub)

**Create:** `shadow/oob/selfhosted.py`

`SelfHostedCollector(OOBCollector)`:
- Placeholder for lab/VPN environment
- `start()` — starts simple HTTP server on random port + DNS listener (stub)
- `stop()` — stops listeners
- Returns local canary URLs like `http://127.0.0.1:PORT/canary-{id}`

Tests: verify start/stop lifecycle, verify canary URLs

- [ ] Step 1: Write tests → run (expect FAIL)
- [ ] Step 2: Implement selfhosted.py (simple stub)
- [ ] Step 3: Run tests → PASS
- [ ] Step 4: Commit

---

**Plan 4 complete.** Payloads + OOB ready → Plan 5 (platform integrations).
