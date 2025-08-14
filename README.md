# SoupSalad

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
  - Async engine (httpx) with HTTP/2, connection pooling, retries/backoff
  - Username lists and password spraying with cooldown windows
  - Rotating proxies (list/Tor) and User-Agent rotation (per worker/request)
  - Auto form discovery (action/method/fields) and per-attempt CSRF refresh
  - Pre-login GET chain (follow redirects) and optional headless JS (Playwright) to prep cookies/tokens
  - Basic SQLi probes, lockout detection with adaptive backoff
  - Checkpoint/resume for long spray runs
  - Export reports to JSON/CSV/HTML (Chart.js RPS graph)
- Save/Load profiles as JSON (legacy .pkl still loadable)
- Safety caps and warnings to avoid unbounded generation

## Install

- Python 3.9+
- Optional: ttkbootstrap for a modern theme
- Pentest requirements:
  - `requests` (sync engine)
  - `httpx` (async engine with HTTP/2)
  - `playwright` (optional, headless JS for pre-login) + browser binaries

```bash
pip install -r requirements.txt
# Pentest extras
pip install requests httpx
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
python SoupSalad.py
```

## Usage (Pentest)

1. Enter profile details (Name, Surname, City, Birthdate)
2. Choose a mode (Brute-force, Smart brute-force, or Smart mutations)
3. Pentest section:
   - Target URL and method, username value, param names
   - Success/failure detection (codes/regex), QPS, Concurrency
   - Headers/Cookies/Proxy/TLS/Timeout as needed
   - Toggle SQLi checks and choose a field
   - Engine: sync or async (httpx), HTTP/2, limits and retry/backoff
   - Rotation: proxies (list/Tor) and User-Agent (file or built-in) per worker/request
   - Usernames & spraying: load username file, pattern generation, aliases, spray passwords file, cooldown settings
   - Checkpoint: enable, select file, resume toggle
   - Form & CSRF: auto-discover form, refresh CSRF each attempt
   - Pre-login chain: enable, list URLs (comma), set per-attempt or per-worker, enable headless JS if needed
4. Reporting panel shows live metrics; use Export buttons for JSON/CSV/HTML
5. Logging: enable “Log to file” to capture attempt-level CSV (timestamp, user, pass, status, latency, success, lockout, proxy, UA)

Notes:
- Brute-force grows exponentially; prefer smart modes and spraying
- Headless JS requires Playwright and installed browser binaries
- Checkpoint applies to spraying; restarts resume from last password/username index

## Profiles

- Save profiles to JSON using "Save Profile". Load them via "Load Profile"
- Legacy .pkl profiles from older versions can still be loaded

## License

MIT
