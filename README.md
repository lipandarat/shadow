# Shadow — Bug Bounty Hunting Assistant

Shadow adalah asisten bug bounty berbasis Python yang terintegrasi dengan **Claude Code**. Sistem berperilaku seperti pentester profesional: menjalankan recon, menemukan celah, memvalidasi temuan secara ketat (bukan teori), membangun exploit chain, menulis laporan, dan belajar dari pekerjaan sebelumnya.

**Shadow berjalan di dalam Claude Code** — bukan di terminal langsung. Anda berinteraksi dengan Shadow melalui slash commands (`/shadow-new`, `/shadow-hunt`, dll) dan Claude Code menggunakan MCP servers serta agen Python di belakang layar.

---

## Daftar Isi

1. [Persyaratan](#persyaratan)
2. [Instalasi](#instalasi)
3. [Konfigurasi API Key](#konfigurasi-api-key)
4. [Cara Penggunaan di Claude Code](#cara-penggunaan-di-claude-code)
5. [Slash Commands](#slash-commands)
6. [MCP Servers](#mcp-servers)
7. [Validation Gate (9 Pertanyaan)](#validation-gate-9-pertanyaan)
8. [Alat Keamanan yang Didukung](#alat-keamanan-yang-didukung)
9. [Struktur Data](#struktur-data)
10. [CLI Utility Commands](#cli-utility-commands)
11. [Pengembangan](#pengembangan)

---

## Persyaratan

- Python 3.11 atau lebih baru
- **Claude Code** (wajib — Shadow berjalan di dalam Claude Code)
- Git

Alat keamanan opsional (sistem auto-detect yang tersedia):

```
nmap, ffuf, nuclei, httpx, subfinder, gau, waybackurls, sqlmap, dalfox, interactsh-client
```

---

## Instalasi

### Langkah 1: Clone proyek

```bash
cd ~
git clone https://github.com/lipandarat/shadow.git
cd shadow
```

### Langkah 2: Jalankan installer

```bash
python install.py install
```

Installer akan:
1. Install package Python (`pip install -e .`)
2. Daftarkan MCP servers ke `~/.claude/settings.json`
3. Install Claude Code hooks ke `~/.claude/settings.json`
4. Copy slash commands ke `~/.claude/commands/`
5. Copy `claude/CLAUDE.md` ke `~/.claude/CLAUDE.md`
6. Buat `~/.shadow/config.yaml` dengan template kosong
7. Jalankan verifikasi otomatis

### Langkah 3: Verifikasi instalasi

```bash
python install.py verify
```

Output yang diharapkan:
```
=== Verification Results ===
  [PASS] Python package imports
  [PASS] MCP server: bounty-platforms
  [PASS] MCP server: writeup-search
  [PASS] Claude Code hooks
  [PASS] Slash commands
  [PASS] MCP dry-run
  [PASS] MCP bundle test

Overall: PASS
```

### Langkah 4: Buka Claude Code

Buka Claude Code di direktori proyek Anda. Shadow sudah siap digunakan via slash commands.

---

## Konfigurasi API Key

Edit `~/.shadow/config.yaml`:

```yaml
platforms:
  hackerone:
    api_key: "YOUR_HACKERONE_API_KEY"
    username: "YOUR_HACKERONE_USERNAME"
  bugcrowd:
    api_key: "YOUR_BUGCROWD_API_KEY"

oob:
  mode: interactsh  # interactsh atau selfhosted
  selfhosted_port: 0

opsec:
  delay_range: [1.0, 3.0]
  max_requests_per_minute: 30
```

Untuk mendapatkan API key:
- **HackerOne**: Settings → API Token → Create API Token
- **Bugcrowd**: Settings → API → Generate Token

---

## Cara Penggunaan di Claude Code

Shadow digunakan **di dalam Claude Code** melalui slash commands. Buka Claude Code dan ketik slash command untuk memulai.

### Alur kerja tipikal:

**1. Buat engagement baru**

Di Claude Code, ketik:
```
/shadow-new hackerone tesla
```

Claude Code akan membuat workspace di `~/.shadow/engagements/hackerone-tesla-YYYYMMDD/` berisi:
- `scope.yaml` — domain in-scope
- `brain.md` — memori dan catatan
- `findings/` — temuan yang tervalidasi
- `endpoints.jsonl` — endpoint yang ditemukan
- `events.jsonl` — audit log semua aksi
- `session.jsonl` — state untuk resume

**2. Sync scope dari platform**

```
/shadow-sync hackerone tesla
```

Mengambil scope, policy, dan hacktivity terbaru dari HackerOne. Membutuhkan API key di config.

**3. Jalankan hunt**

```
/shadow-hunt https://tesla.com --vuln-class sqli
```

Claude Code akan:
1. Cek scope — berhenti jika target out-of-scope
2. Init OPSEC — set rate limit, randomize headers
3. Deteksi tool yang tersedia
4. Jalankan recon — kumpulkan endpoints
5. Fingerprint target — deteksi framework, DB, WAF
6. Generate adaptive payloads — bukan wordlist statis
7. Probe dengan payloads dan tool yang tersedia
8. Setup OOB canary untuk blind vulnerabilities
9. Setiap anomali → validation gate (9 pertanyaan)
10. PASS → simpan ke `findings/`
11. FAIL → catat dead end di `brain.md`

**4. Validasi finding**

```
/shadow-validate F001
```

Menjalankan 9-question gate pada finding F001. Menampilkan PASS/FAIL per pertanyaan.

**5. Build exploit chain**

```
/shadow-chain F001
```

Mencari findings lain yang berhubungan dan membangun exploit chain dengan severity gabungan.

**6. Cek duplikat**

```
/shadow-dupcheck F001
```

Memeriksa apakah F001 adalah duplikat dari finding lokal atau hacktivity platform.

**7. Generate laporan**

```
/shadow-report
```

Menghasilkan laporan Markdown draft. **Tidak pernah auto-submit.** Claude Code akan menampilkan draft untuk review sebelum submission.

**8. Catat hasil dari platform**

```
/shadow-learn F001 accepted --bounty 500 --vuln-type sqli
```

Status yang valid: `accepted`, `duplicate`, `informational`, `not_applicable`

**9. Kelola OOB listener**

```
/shadow-oob start
/shadow-oob check
/shadow-oob stop
```

---

## Slash Commands

Semua slash commands tersedia di Claude Code setelah instalasi:

| Command | Fungsi |
|---------|--------|
| `/shadow-new <platform> <program>` | Buat engagement workspace baru |
| `/shadow-sync <platform> <program>` | Sync scope dari platform |
| `/shadow-hunt <target> [--vuln-class X]` | Jalankan hunt cycle |
| `/shadow-validate <finding_id>` | Jalankan 9-question gate manual |
| `/shadow-chain <finding_id>` | Build exploit chain |
| `/shadow-report` | Generate laporan draft |
| `/shadow-dupcheck <finding_id>` | Cek duplikat |
| `/shadow-learn <id> <status> [--bounty N]` | Catat hasil platform |
| `/shadow-oob start\|stop\|check` | Kelola OOB listener |

---

## MCP Servers

Dua MCP server tersedia untuk Claude Code:

### `bounty-platforms`

| Tool | Fungsi |
|------|--------|
| `sync_program(platform, slug)` | Fetch scope + policy, simpan ke scope.yaml |
| `list_programs(platform)` | Daftar program aktif |
| `get_hacktivity(platform, slug)` | Laporan publik terbaru |
| `check_scope(url, engagement_id)` | Cek apakah URL in-scope |

### `writeup-search`

| Tool | Fungsi |
|------|--------|
| `search_writeups(query, platform)` | Cari writeup relevan |
| `get_writeup(url)` | Ambil konten writeup |
| `similar_findings(vuln_type)` | Temuan serupa dari hacktivity |

---

## Validation Gate (9 Pertanyaan)

Setiap finding WAJIB lulus semua 9 pertanyaan sebelum disimpan. Gate dijalankan di `store.save_finding()` — tidak bisa di-bypass dari layer manapun.

| # | Pertanyaan | FAIL jika |
|---|-----------|-----------|
| 1 | Reproducible? | Tidak bisa diulang |
| 2 | In-scope? | Domain tidak ada di scope.yaml |
| 3 | Ada bukti konkret? | Tidak ada request/response/screenshot/PoC/OOB |
| 4 | Severity realistis? | Inflated tanpa justifikasi CVSS |
| 5 | Bukan false positive? | Ada di daftar known FP |
| 6 | Sudah cek duplikat? | Fingerprint match dengan finding existing |
| 7 | Ada impact nyata? | Hanya informational, tidak ada kerugian |
| 8 | Exploitable secara nyata? | Hanya teori tanpa bukti |
| 9 | Bukan halusinasi AI? | Frasa teoritis tanpa evidence |

**Finding yang hanya berisi teori tanpa bukti eksploitasi nyata akan otomatis ditolak.**

---

## Alat Keamanan yang Didukung

Shadow auto-detect alat yang tersedia via `shutil.which()`. Alat tidak wajib — sistem tetap berjalan dengan metode manual jika alat tidak ada.

| Alat | Fungsi |
|------|--------|
| `nmap` | Network scanning |
| `ffuf` | Directory/parameter fuzzing |
| `nuclei` | Template-based scanning |
| `httpx` | HTTP probing |
| `subfinder` | Subdomain enumeration |
| `gau` | URL collection |
| `waybackurls` | Historical URLs |
| `sqlmap` | SQL injection |
| `dalfox` | XSS scanning |
| `interactsh-client` | OOB detection |

### Instalasi alat (opsional)

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# dalfox
go install github.com/hahwul/dalfox/v2@latest
```

---

## Struktur Data

### Workspace engagement

```
~/.shadow/
├── config.yaml                     # API keys, preferensi global
└── engagements/
    └── hackerone-tesla-20260519/
        ├── scope.yaml              # Domain in-scope
        ├── brain.md                # Memori, dead ends, pola
        ├── endpoints.jsonl         # Endpoint yang ditemukan
        ├── events.jsonl            # Audit log semua aksi
        ├── session.jsonl           # State untuk resume
        └── findings/
            ├── F001-sqli-login.yaml
            └── F002-xss-profile.yaml
```

### Format finding (YAML)

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
status: validated
evidence:
  request: |
    POST /login HTTP/1.1
    Host: tesla.com
    username=admin'--&password=x
  response: |
    HTTP/1.1 200 OK
    Welcome admin
reproduction_steps:
  - Buka https://tesla.com/login
  - Masukkan payload admin'-- di field username
  - Login berhasil sebagai admin
impact: Bypass autentikasi, akses akun admin tanpa password
fix: Gunakan parameterized query / prepared statement
fingerprint: sha256:a3f2...
created_at: 2026-05-19T10:00:00Z
validated_at: 2026-05-19T10:05:00Z
```

---

## CLI Utility Commands

Beberapa perintah CLI tersedia untuk setup dan maintenance. **Ini bukan cara utama menggunakan Shadow** — gunakan slash commands di Claude Code untuk hunting.

### Installer

```bash
python install.py install    # Install Shadow dan konfigurasi Claude Code
python install.py verify     # Verifikasi semua komponen terpasang
python install.py render     # Tampilkan konfigurasi aktif
python install.py uninstall  # Hapus konfigurasi Claude Code
```

### MCP server dry-run (untuk debugging)

```bash
python -m shadow.cli.main mcp serve bounty-platforms --dry-run
python -m shadow.cli.main mcp serve writeup-search --dry-run
```

### Buat engagement dari terminal

```bash
shadow new hackerone tesla
```

Ini satu-satunya CLI command yang berfungsi penuh di terminal. Semua command lain (`hunt`, `validate`, `report`, dll) dirancang untuk dijalankan oleh Claude Code, bukan langsung dari terminal.

---

## Pengembangan

### Setup development environment

```bash
git clone https://github.com/lipandarat/shadow.git
cd shadow
pip install -e ".[dev]"
```

### Jalankan tests

```bash
pytest
pytest -q                          # ringkas
pytest tests/test_store.py -v      # satu file
pytest -k "test_save_finding" -v   # filter nama
```

### Struktur package

```
shadow/
├── core/          # Foundation: models, store, validate, scope, audit, dll
├── agents/        # Agen: recon, hunt, validate, chain, report, dll
├── payloads/      # Payload engine: fingerprint, mutator, feedback
├── oob/           # OOB detection: interactsh, selfhosted
├── platforms/     # Platform API: hackerone, bugcrowd
├── mcp/           # MCP servers untuk Claude Code
├── hooks/         # Claude Code PreToolUse hooks
└── cli/           # CLI entry point (installer + new command)
```

### Uninstall

```bash
python install.py uninstall
```

Data engagement di `~/.shadow/` tidak dihapus otomatis. Untuk hapus semua data:

```bash
# Windows
Remove-Item -Recurse -Force "$env:USERPROFILE\.shadow"

# Linux/macOS
rm -rf ~/.shadow
```
