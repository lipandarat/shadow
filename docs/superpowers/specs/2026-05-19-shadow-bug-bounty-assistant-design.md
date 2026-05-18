# Shadow — Bug Bounty Assistant Design Spec
**Date:** 2026-05-19  
**Status:** Approved  
**Target user:** Solo researcher, CLI-first, local deployment  
**AI integration:** Claude Code / Claude API only  
**Platforms:** HackerOne + Bugcrowd  
**Storage:** File-based (JSON/YAML/Markdown)

---

## 1. Overview

Shadow adalah perangkat lunak asisten bug bounty berbasis Python untuk pengujian resmi. Sistem berperilaku seperti pentester profesional: menjalankan recon, menemukan celah, memvalidasi temuan secara ketat (bukan teori), membangun exploit chain, menulis laporan, dan belajar dari pekerjaan sebelumnya.

Sistem dibangun sebagai satu Python package (`shadow`) dengan plugin architecture, MCP server untuk integrasi Claude Code, dan installer CLI yang mengurus semua konfigurasi.

---

## 2. Arsitektur & Struktur Direktori

### Package structure

```
shadow/
├── pyproject.toml
├── install.py                      # CLI installer: install/verify/render/uninstall
├── shadow/
│   ├── __init__.py
│   ├── cli/
│   │   ├── main.py                 # entry point: `shadow` command
│   │   └── commands/               # sub-commands
│   │       ├── new.py
│   │       ├── sync.py
│   │       ├── hunt.py
│   │       ├── validate.py
│   │       ├── chain.py
│   │       ├── report.py
│   │       ├── dupcheck.py
│   │       ├── learn.py
│   │       └── oob.py
│   ├── core/
│   │   ├── engagement.py           # buat/load engagement workspace
│   │   ├── store.py                # baca/tulis findings dengan pre-save hook
│   │   ├── brain.py                # memori persisten per engagement
│   │   ├── toolcheck.py            # auto-detect tool keamanan tersedia
│   │   ├── audit.py                # append-only events.jsonl logger
│   │   ├── scope.py                # scope enforcement + @require_in_scope
│   │   ├── opsec.py                # rate limiting, user-agent randomization
│   │   ├── cvss.py                 # CVSS 3.1 auto-calculation
│   │   ├── dedup.py                # fingerprint-based deduplication
│   │   └── session.py              # session replay & resume
│   ├── agents/
│   │   ├── recon.py
│   │   ├── hunt.py
│   │   ├── validate.py             # 9-question validation gate
│   │   ├── chain.py
│   │   ├── report.py
│   │   └── dupcheck.py
│   ├── payloads/
│   │   ├── engine.py               # adaptive payload engine
│   │   ├── fingerprint.py          # target fingerprinting
│   │   ├── mutator.py              # mutation & WAF bypass
│   │   └── feedback.py             # response anomaly feedback loop
│   ├── oob/
│   │   ├── collector.py            # OOB canary generator & hit checker
│   │   ├── interactsh.py           # interactsh-client integration
│   │   └── selfhosted.py           # local DNS + HTTP listener
│   ├── platforms/
│   │   ├── base.py
│   │   ├── hackerone.py
│   │   └── bugcrowd.py
│   ├── hooks/
│   │   ├── pre_save_check.py       # Claude Code PreToolUse hook (findings/)
│   │   └── scope_check.py          # Claude Code PreToolUse hook (Bash)
│   └── mcp/
│       ├── server.py
│       ├── bounty_platforms.py
│       └── writeup_search.py
├── tests/
│   ├── test_store.py
│   ├── test_engagement.py
│   ├── test_validate.py
│   ├── test_scope.py
│   ├── test_dedup.py
│   ├── test_payload_engine.py
│   ├── test_oob.py
│   └── test_mcp_bundle.py
└── claude/
    ├── CLAUDE.md
    └── commands/
        ├── new.md
        ├── sync.md
        ├── hunt.md
        ├── validate.md
        ├── report.md
        ├── dupcheck.md
        ├── learn.md
        ├── chain.md
        └── oob.md
```

### Data storage (`~/.shadow/`)

```
~/.shadow/
├── config.yaml                     # API keys, preferensi global
└── engagements/
    └── hackerone-tesla-20260519/
        ├── scope.yaml              # in-scope domains, IPs, endpoints
        ├── brain.md                # memori, dead ends, pola yang dipelajari
        ├── endpoints.jsonl         # endpoint yang ditemukan
        ├── events.jsonl            # audit log append-only: SEMUA aksi agen (what happened)
        ├── session.jsonl           # session state untuk resume: step mana yang sudah done (where to continue)
        └── findings/
            ├── F001-sqli-login.yaml
            └── F002-xss-profile.yaml
```

### Finding schema (`findings/FXXX.yaml`)

```yaml
id: F001
title: SQL Injection di /login parameter username
vuln_class: sqli
severity: high
cvss_score: 8.6
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
target: https://tesla.com/login
parameter: username
method: POST
status: validated          # draft | validated | reported | accepted | duplicate
evidence:
  request: |
    POST /login HTTP/1.1
    Host: tesla.com
    username=admin'--&password=x
  response: |
    HTTP/1.1 200 OK
    Welcome admin
  screenshot: findings/F001-screenshot.png
  poc: findings/F001-poc.py
reproduction_steps:
  - Buka https://tesla.com/login
  - Masukkan payload `admin'--` di field username
  - Password bisa diisi apa saja
  - Login berhasil sebagai admin
impact: Bypass autentikasi, akses akun admin tanpa password
fix: Gunakan parameterized query / prepared statement
oob_hit: null
fingerprint: sha256:a3f2...   # untuk dedup
created_at: 2026-05-19T10:00:00Z
validated_at: 2026-05-19T10:05:00Z
```

---

## 3. Alur Kerja Agen

### Siklus hidup engagement

```
shadow new hackerone tesla
  └─> buat ~/.shadow/engagements/hackerone-tesla-YYYYMMDD/
      scope.yaml kosong, brain.md kosong, events.jsonl kosong

shadow sync hackerone tesla
  └─> fetch scope + policy + hacktivity via API
      simpan ke scope.yaml + brain.md
      catat ke events.jsonl

shadow hunt target.com --vuln-class sqli
  └─> scope_check(target) → STOP jika out-of-scope
      opsec.init() → set rate limit, randomize headers
      toolcheck() → deteksi tool tersedia
      recon agent → kumpulkan endpoints → simpan endpoints.jsonl
      hunt agent:
        fingerprint(target) → target profile
        adaptive_payload_engine(profile) → custom payloads
        oob.get_canary(finding_id) → siapkan OOB listener
        jalankan tool + probe dengan payloads
        setiap anomali → validate gate (9 pertanyaan)
        jika PASS → store.save_finding() → tulis findings/
        jika FAIL → catat dead end di brain.md
      catat semua langkah ke events.jsonl

shadow chain F001
  └─> cari findings lain yang bisa dirangkai dengan F001
      hasilkan exploit chain dengan severity gabungan
      simpan sebagai finding baru dengan type: chain

shadow report
  └─> dupcheck → cek fingerprint vs hacktivity platform
      cvss.calculate() untuk setiap finding
      report agent → generate YAML + Markdown
      tampilkan draft → TIDAK auto-submit
      tunggu konfirmasi manual

shadow learn F001 accepted --bounty 500 --vuln-type sqli
  └─> catat hasil ke brain.md
      update pola: vuln class diterima, severity realistis
      agen berikutnya prioritaskan area serupa
```

### Tool auto-detection (`toolcheck.py`)

```python
TOOLS = {
    "nmap":        "network scanning",
    "ffuf":        "directory/parameter fuzzing",
    "nuclei":      "template-based scanning",
    "httpx":       "HTTP probing",
    "subfinder":   "subdomain enumeration",
    "gau":         "URL collection",
    "waybackurls": "historical URLs",
    "sqlmap":      "SQL injection",
    "dalfox":      "XSS scanning",
    "interactsh-client": "OOB detection",
}
# Deteksi via shutil.which()
# Tool tidak tersedia → agen pakai metode manual/alternatif
# Hasil disimpan ke brain.md saat engagement init
```

---

## 4. Validation Gate (9 Pertanyaan)

Setiap finding WAJIB lulus semua 9 pertanyaan sebelum bisa disimpan. Gate dijalankan di `store.save_finding()` — tidak bisa di-bypass dari layer manapun.

| # | Pertanyaan | FAIL jika |
|---|-----------|-----------|
| 1 | Reproducible? | Hanya terjadi sekali, tidak bisa diulang |
| 2 | In-scope? | Domain/IP tidak ada di scope.yaml |
| 3 | Ada bukti konkret? | Tidak ada request/response/screenshot/PoC |
| 4 | Severity realistis? | Inflated tanpa justifikasi CVSS |
| 5 | Bukan false positive yang diketahui? | Ada di daftar known FP |
| 6 | Sudah cek duplikat? | Fingerprint match dengan finding existing |
| 7 | Ada impact nyata? | Hanya informational, tidak ada kerugian |
| 8 | Exploitable secara nyata? | Deskripsi hanya teori tanpa bukti eksploitasi |
| 9 | Bukan halusinasi AI? | Mengandung frasa teoritis tanpa evidence |

**Anti-hallucination filter (pertanyaan 8 & 9):**

```python
THEORY_PHRASES = [
    "could potentially", "may allow", "it is possible",
    "attacker could", "might be able", "theoretically",
    "could lead to", "may result in", "it may be possible",
    "an attacker might", "this could allow",
]

REQUIRED_EVIDENCE_TYPES = [
    "request",      # HTTP request aktual
    "response",     # HTTP response aktual
    "screenshot",   # screenshot hasil eksploitasi
    "poc",          # proof-of-concept code yang bisa dijalankan
    "oob_hit",      # OOB callback (untuk blind vulnerabilities)
]

def check_exploitability(finding: Finding) -> GateResult:
    if not finding.has_any_evidence(REQUIRED_EVIDENCE_TYPES):
        return FAIL("Tidak ada bukti eksploitasi nyata — hanya teori")
    if any(p in finding.description.lower() for p in THEORY_PHRASES):
        return FAIL("Deskripsi teoritis tanpa bukti konkret")
    return PASS
```

**No-impact filter (pertanyaan 7):**

Finding harus bisa menjawab: *"Apa kerugian nyata jika ini dieksploitasi?"*

Contoh FAIL: header disclosure, SSL expiry, directory listing tanpa file sensitif, version disclosure tanpa known CVE.

---

## 5. Pre-Save Hook & Claude Code Hooks

### Layer 1 — Python level (`store.py`)

```python
class FindingStore:
    def save_finding(self, finding: Finding) -> SaveResult:
        gate_result = ValidationGate.run(finding)  # 9 pertanyaan
        if not gate_result.passed:
            self._record_dead_end(finding, gate_result.reasons)
            raise ValidationFailed(gate_result.reasons)
        dedup_result = DedupEngine.check(finding)
        if dedup_result.is_duplicate:
            raise DuplicateFinding(dedup_result.match)
        finding.cvss_score = CVSSCalculator.calculate(finding)
        finding.fingerprint = FingerprintEngine.compute(finding)
        self._write(finding)
        self.audit.log("finding_saved", finding.id)
```

### Layer 2 — Claude Code level (`~/.claude/settings.json`)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "python -m shadow.hooks.pre_save_check"
        }]
      },
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "python -m shadow.hooks.scope_check"
        }]
      }
    ]
  }
}
```

Hook `pre_save_check` intercept setiap Write/Edit ke path `findings/` dan jalankan validation gate.  
Hook `scope_check` intercept setiap Bash command dan verifikasi target in-scope sebelum eksekusi.

---

## 6. Scope Enforcement

Setiap tool call yang menyentuh target eksternal wajib lewat scope check:

```python
def require_in_scope(func):
    @wraps(func)
    def wrapper(target, *args, **kwargs):
        if not ScopeEngine.is_in_scope(target):
            audit.log("scope_violation_blocked", target=target, func=func.__name__)
            raise ScopeViolation(f"{target} tidak ada di scope.yaml")
        return func(target, *args, **kwargs)
    return wrapper

@require_in_scope
def run_nuclei(target, templates): ...

@require_in_scope
def run_ffuf(target, wordlist): ...

@require_in_scope
def send_request(url, method, data): ...
```

Scope violation dicatat ke `events.jsonl` dan tidak pernah silent-fail.

---

## 7. OPSEC Guard

```python
class OpsecGuard:
    DEFAULT_DELAY_RANGE = (1.0, 3.0)   # detik antar request
    MAX_REQUESTS_PER_MINUTE = 30
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ]  # rotasi user-agent realistis browser biasa
    
    def before_request(self, target: str):
        self._enforce_rate_limit(target)
        self._randomize_headers()
        self._check_request_volume()
    
    def _check_request_volume(self):
        if self.requests_last_minute > self.MAX_REQUESTS_PER_MINUTE:
            audit.log("opsec_warning", "request rate terlalu tinggi")
            time.sleep(random.uniform(5, 15))
```

---

## 8. Adaptive Payload Engine

### Fase 1 — Target fingerprinting

```python
class TargetFingerprinter:
    def profile(self, target: str) -> TargetProfile:
        return TargetProfile(
            framework=self._detect_framework(),    # Laravel, Django, Spring, dll
            db_type=self._detect_db(),             # MySQL, PostgreSQL, MSSQL, dll
            waf_vendor=self._detect_waf(),         # ModSecurity, Cloudflare, dll
            filtered_chars=self._probe_filter(),   # karakter yang di-strip/block
            error_verbosity=self._check_errors(),  # verbose/silent
            timing_baseline=self._measure_timing() # ms baseline untuk blind
        )
```

### Fase 2 — Anomaly-based payload generation

```python
class AdaptivePayloadEngine:
    def generate(self, profile: TargetProfile, vuln_class: str) -> list[Payload]:
        # Generate berdasarkan profil target, BUKAN ambil dari wordlist
        base = self._select_syntax(profile.db_type, vuln_class)
        encodings = self._select_encodings(profile.filtered_chars)
        bypasses = self._select_waf_bypasses(profile.waf_vendor)
        return self._combine(base, encodings, bypasses)
```

### Fase 3 — Feedback loop

```python
class PayloadFeedback:
    def analyze_response(self, payload, response) -> FeedbackSignal:
        anomalies = self._detect_anomalies(response)
        # Status code berbeda, timing spike, error message baru,
        # response length berbeda → generate variasi lebih lanjut
        if anomalies:
            return self.engine.generate_variants(payload, anomalies)
        return DISCARD
```

Payload yang tidak menghasilkan anomali dibuang. Payload yang menghasilkan anomali dikembangkan lebih lanjut.

---

## 9. OOB Detection Infrastructure

### Mode 1 — Interactsh (default jika tersedia)

```python
class InteractshCollector:
    def get_canary(self, finding_id: str) -> str:
        # shadow-{engagement_id}-{finding_id}.interactsh.com
        return f"shadow-{self.engagement_id}-{finding_id}.{self.interactsh_domain}"
    
    def check_hit(self, finding_id: str) -> OOBHit | None:
        # Poll interactsh API untuk DNS/HTTP callback
        hits = self.client.poll()
        return next((h for h in hits if finding_id in h.correlation_id), None)
```

### Mode 2 — Self-hosted (untuk lab/VPN)

```python
class SelfHostedCollector:
    # DNS server lokal (port 53) + HTTP listener (port 80/443)
    # shadow oob start → jalankan kedua listener
    # shadow oob stop  → hentikan
```

### Integrasi ke validation gate

OOB hit diterima sebagai bukti konkret untuk pertanyaan 3 dan 8. Blind SQLi/SSRF/CMDi/XXE yang menghasilkan OOB hit lulus gate dengan `evidence.oob_hit` terisi.

---

## 10. Deduplication Fingerprinting

```python
class FingerprintEngine:
    def compute(self, finding: Finding) -> str:
        # Fingerprint = hash(endpoint + vuln_class + parameter + payload_type)
        key = f"{finding.target}:{finding.vuln_class}:{finding.parameter}"
        return hashlib.sha256(key.encode()).hexdigest()
    
class DedupEngine:
    def check(self, finding: Finding) -> DedupResult:
        fp = FingerprintEngine.compute(finding)
        # Cek vs findings/ lokal
        local_match = self.store.find_by_fingerprint(fp)
        if local_match:
            return DedupResult(is_duplicate=True, match=local_match.id)
        # Cek vs hacktivity platform
        platform_match = self.platform.search_hacktivity(finding)
        if platform_match:
            return DedupResult(is_duplicate=True, match=platform_match.url)
        return DedupResult(is_duplicate=False)
```

---

## 11. CVSS 3.1 Auto-Calibration

```python
class CVSSCalculator:
    def calculate(self, finding: Finding) -> tuple[float, str]:
        # Hitung dari metadata finding
        vector = CVSSVector(
            AV=self._attack_vector(finding),      # N/A/L/P
            AC=self._attack_complexity(finding),   # L/H
            PR=self._privileges_required(finding), # N/L/H
            UI=self._user_interaction(finding),    # N/R
            S=self._scope(finding),                # U/C
            C=self._confidentiality(finding),      # N/L/H
            I=self._integrity(finding),            # N/L/H
            A=self._availability(finding),         # N/L/H
        )
        score = vector.calculate()
        return score, str(vector)
```

Severity label otomatis dari score: Critical (9.0+), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9).

---

## 12. Session Replay & Resume

```python
# Setiap langkah agen ditulis ke session.jsonl SEBELUM dieksekusi
class SessionManager:
    def checkpoint(self, step: str, state: dict):
        self.session_log.append({
            "step": step,
            "state": state,
            "timestamp": now(),
            "status": "pending"
        })
    
    def mark_done(self, step: str):
        self.session_log.update(step, status="done")
    
    def get_resume_point(self) -> str | None:
        # Return step terakhir yang status "pending"
        pending = [s for s in self.session_log if s["status"] == "pending"]
        return pending[0] if pending else None

# shadow hunt --resume → skip semua step yang sudah "done"
```

---

## 13. Learning Loop

```bash
shadow learn F001 accepted --bounty 500 --vuln-type sqli
```

```python
class LearningEngine:
    def record(self, finding_id, status, bounty=None, vuln_type=None):
        # Catat ke brain.md
        entry = LearningEntry(
            finding_id=finding_id,
            status=status,           # accepted/duplicate/informational/na
            bounty=bounty,
            vuln_type=vuln_type,
            program=self.engagement.program,
            timestamp=now(),
        )
        self.brain.append_learning(entry)
        # Update pola untuk agen berikutnya
        self.brain.update_patterns(entry)
    
    def get_priority_areas(self) -> list[str]:
        # Return vuln class yang paling sering accepted di program ini
        return self.brain.top_accepted_vuln_classes()
```

---

## 14. MCP Server

### `bounty-platforms` MCP

```
tools:
  sync_program(platform, slug)      → fetch scope + policy, simpan ke scope.yaml
  list_programs(platform)           → daftar program aktif
  get_hacktivity(platform, slug)    → laporan publik terbaru
  check_scope(url, engagement_id)   → apakah URL in-scope?
```

### `writeup-search` MCP

```
tools:
  search_writeups(query, platform)  → cari writeup relevan
  get_writeup(url)                  → ambil konten writeup
  similar_findings(vuln_type)       → temuan serupa dari hacktivity
```

Kedua server diimplementasi dengan `mcp` Python SDK, transport `stdio`, didaftarkan ke Claude Code via `install.py`.

---

## 15. Installer CLI (`install.py`)

```bash
python install.py install     # install package + daftarkan MCP + copy slash commands
python install.py verify      # cek semua komponen terpasang dan berfungsi
python install.py render      # tampilkan konfigurasi aktif
python install.py uninstall   # hapus bersih semua konfigurasi Claude Code
```

### `install` melakukan:
1. `pip install -e .`
2. Tulis MCP server entries ke `~/.claude/settings.json`
3. Tulis Claude Code hooks ke `~/.claude/settings.json`
4. Copy slash command files ke `~/.claude/commands/`
5. Buat `~/.shadow/config.yaml` jika belum ada
6. Jalankan `verify` otomatis

### `verify` melakukan:
1. Import semua modul Python → tidak ada ImportError
2. Cek MCP entries ada di `~/.claude/settings.json`
3. Cek hooks ada di `~/.claude/settings.json`
4. Cek slash commands ada di `~/.claude/commands/`
5. Jalankan `shadow mcp serve --dry-run`
6. Jalankan `tests/test_mcp_bundle.py`

### `uninstall` melakukan:
1. Hapus MCP entries dari `~/.claude/settings.json`
2. Hapus hooks dari `~/.claude/settings.json`
3. Hapus slash commands dari `~/.claude/commands/`
4. `pip uninstall shadow`
5. Data engagement di `~/.shadow/` TIDAK dihapus (perlu konfirmasi eksplisit)

---

## 16. Test Suite

| File | Yang diuji |
|------|-----------|
| `test_store.py` | Pre-save hook, validation gate enforcement |
| `test_engagement.py` | Buat/load engagement, scope.yaml parsing |
| `test_validate.py` | 9-question gate, anti-hallucination filter |
| `test_scope.py` | Scope enforcement, ScopeViolation raise |
| `test_dedup.py` | Fingerprint computation, duplicate detection |
| `test_payload_engine.py` | Fingerprinting, payload generation, feedback loop |
| `test_oob.py` | Canary generation, hit detection (mock) |
| `test_mcp_bundle.py` | Tool definitions konsisten antara CLAUDE.md dan implementasi |

### `test_mcp_bundle.py` — bundle drift check:
- Semua tool di `CLAUDE.md` ada di implementasi MCP
- Semua tool di implementasi terdaftar di `CLAUDE.md`
- Schema parameter konsisten
- Server bisa di-instantiate tanpa side effects

---

## 17. Slash Commands (Claude Code)

| Command | Fungsi |
|---------|--------|
| `/new <platform> <program>` | Buat engagement workspace baru |
| `/sync <platform> <program>` | Sync scope + policy dari platform |
| `/hunt <target> [--vuln-class]` | Jalankan hunt cycle |
| `/validate <finding>` | Jalankan 9-question gate manual |
| `/chain <finding_id>` | Build exploit chain dari finding |
| `/report` | Generate laporan draft |
| `/dupcheck <vuln_type>` | Cek duplikat manual |
| `/learn <id> <status> [--bounty]` | Catat hasil platform response |
| `/oob start\|stop\|check` | Kelola OOB listener |

---

## 18. Keputusan Desain & Trade-offs

| Keputusan | Alasan |
|-----------|--------|
| File-based storage (bukan SQLite) | Mudah di-git, diff-able, tidak perlu server |
| Validation gate di `store.py` bukan di agen | Tidak bisa di-bypass oleh agen manapun |
| Adaptive payload (bukan wordlist) | WAF tidak bisa signature-match payload baru |
| Dua lapis hook (Python + Claude Code) | Defense in depth, tidak ada single point of failure |
| CVSS 3.1 otomatis | Mencegah severity inflation, kredibel di mata triager |
| OOB via interactsh default | Tidak perlu server sendiri, gratis, sudah terbukti |
| Session replay via events.jsonl | Konsisten dengan pola yang sudah ada di engagement lama |
| Learning loop ke brain.md | Agen berikutnya baca konteks yang sama |
