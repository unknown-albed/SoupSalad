# ForceCraft

A modernized, GUI-based Password List Generator built with Python. Generate custom password dictionaries from profile data using either character brute-force or realistic smart mutations.

## Highlights

- Modern themed UI (uses ttkbootstrap when available)
- Three generation modes:
  - Brute-force over a chosen character set and length range
  - Smart brute-force (prioritized, reduced charset based on your inputs)
  - Smart mutations from tokens (name, surname, city, birthdate, optional wordlist) with case/leet/suffix variations
- Live progress with ETA, sample preview, logs, and a reporting panel (RPS, latency percentiles, HTTP code table)
- Output to .txt or compressed .txt.gz
- Optional Pentest mode (authorized testing only):
  - HTTP GET/POST attempts with rate limiting, concurrency, and cancel
  - SSH spray (paramiko), FTP/FTPS spray (ftplib/FTP_TLS) with safe caps
  - Async engine (httpx) with HTTP/2, connection pooling, retries/backoff
  - Username lists and password spraying with cooldown windows
  - Rotating proxies (list/Tor) and User-Agent rotation (per worker/request)
  - Auto form discovery (action/method/fields) and per-attempt CSRF refresh
  - Pre-login GET chain (follow redirects) and optional headless JS (Playwright) to prep cookies/tokens
  - Basic SQLi probes, lockout detection with adaptive backoff
  - Checkpoint/resume for long spray runs
  - Fail-fast guard (stop or global backoff) on high error-rate in a time window
  - Export reports to JSON/CSV/HTML (Chart.js RPS graph) and OSCP Markdown/DOCX
- Save/Load profiles as JSON (legacy .pkl still loadable)
- Safety caps and warnings to avoid unbounded generation
- CLI automation: multi-target runs (targets file), Nmap XML import (HTTP), recon helper

## Install

- Python 3.9+
- Optional: ttkbootstrap for a modern theme
- Pentest requirements:
  - `requests` (sync engine)
  - `httpx` (async engine with HTTP/2)
  - `paramiko` (SSH)
  - `python-docx` (DOCX export)
  - `playwright` (optional, headless JS for pre-login) + browser binaries

```bash
pip install -r requirements.txt
# Pentest extras
pip install requests httpx paramiko python-docx
# Optional headless browser for pre-login JS
pip install playwright
playwright install chromium
```

If you prefer not to install ttkbootstrap, the app will fall back to standard Tkinter ttk.

## OS-specific setup

### Linux (Debian/Ubuntu)

- Ensure Tk and venv tools are present:
```bash
sudo apt update
sudo apt install -y python3-tk python3-venv
```
- Create and activate a virtual environment, then install deps:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install requests httpx
# For headless JS pre-login
pip install playwright && playwright install chromium
```

### Windows (PowerShell)

- Install Python 3.9+ from python.org (make sure “Add Python to PATH” is checked)
- Create and activate venv, then install deps:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install requests httpx
# Optional headless JS
pip install playwright
playwright install chromium
```
- Tkinter ships with standard Python installers. If it’s missing, reinstall Python choosing the full feature set.

### macOS

- Using Homebrew Python:
```bash
brew install python-tk@3
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install requests httpx
# Optional headless JS
pip install playwright && playwright install chromium
```
- If you use the official Python.org installer, Tkinter is included; you can skip the Homebrew tk install.

## Run

```bash
python ForceCraft.py
```

## CLI automation

- Multi-target from a file (HTTP/SSH/FTP depending on profile `protocol`):
```bash
python ForceCraft.py \
  --profile myprofile.json \
  --targets-file targets.txt \
  --out-dir ./out \
  --aggregate-md ./out/all.md \
  --aggregate-docx ./out/all.docx \
  --no-gui
```

- Nmap XML import (HTTP/HTTPS extraction):
```bash
python ForceCraft.py \
  --profile http_profile.json \
  --nmap-xml scan.xml \
  --out-dir ./out \
  --aggregate-md ./out/all.md \
  --no-gui
```

- Single target (headless) with OSCP outputs and DOCX template:
```bash
python ForceCraft.py \
  --profile profiles/oscp-safe-flow.json \
  --out-dir ./bundle \
  --report-md ./bundle/report.md \
  --report-docx ./bundle/report.docx \
  --docx-template ./template.docx \
  --no-gui
```

Environment alternative for template: set `DOCX_TEMPLATE` or `FORCECRAFT_DOCX_TEMPLATE`.

## Usage (Pentest)

1. Enter profile details (Name, Surname, City, Birthdate)
2. Choose a mode (Brute-force, Smart brute-force, or Smart mutations)
3. Pentest section:
   - Protocol: HTTP, SSH, FTP/FTPS
   - Target URL and method (HTTP) or host/port (SSH/FTP), username value, param names (HTTP)
   - Success/failure detection (HTTP codes/regex or protocol return codes), QPS, Concurrency
   - Headers/Cookies/Proxy/TLS/Timeout as needed
   - Toggle SQLi checks and choose a field
   - Engine: sync or async (httpx), HTTP/2, limits and retry/backoff
   - Rotation: proxies (list/Tor) and User-Agent (file or built-in) per worker/request
   - Usernames & spraying: load username file, pattern generation, aliases, spray passwords file, cooldown settings
   - Checkpoint: enable, select file, resume toggle
   - Form & CSRF: auto-discover form, refresh CSRF each attempt (HTTP)
   - Pre-login chain: enable, list URLs (comma), set per-attempt or per-worker, enable headless JS if needed (HTTP)
   - Fail-fast guard: stop or global backoff when error-rate exceeds threshold in a window
   - FTP: TLS and Passive toggles
4. Reporting panel shows live metrics; use Export buttons for JSON/CSV/HTML/MD/DOCX
5. Logging: enable “Log to file” to capture attempt-level CSV (timestamp, user, pass, status, latency, success, lockout, error, proxy, UA)

Notes:
- Brute-force grows exponentially; prefer smart modes and spraying
- Headless JS requires Playwright and installed browser binaries
- Checkpoint applies to spraying; restarts resume from last password/username index
- Evidence Bundle includes credentials.csv/txt, artifacts, HAR, screenshot, and report files

## Profiles

- Save profiles to JSON using "Save Profile". Load them via "Load Profile"
- Legacy .pkl profiles from older versions can still be loaded

## Performance and stealth tips

- Use Safe Mode caps conservatively (e.g., QPS ≤ 1, concurrency ≤ 2) for exam targets
- Prefer Smart mutations and spraying over full brute-force
- Enable fail-fast backoff to auto-throttle during transient spikes; 30–60s is a good backoff
- HTTP: lower retries/backoff; enable proxy/UA rotation only where permitted; async off when using Flow
- SSH/FTP: short timeouts (10–15s), small concurrency; avoid hammering; rely on global backoff
- Use allowlists to avoid accidental out-of-scope traffic
- Capture artifacts selectively (limit failures N) to reduce disk churn

## License

MIT
