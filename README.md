# SoupSalad

A modernized, GUI-based Password List Generator built with Python. Generate custom password dictionaries from profile data using either character brute-force or realistic smart mutations.

## Highlights

- Modern themed UI (uses ttkbootstrap when available)
- Three generation modes:
  - Brute-force over a chosen character set and length range
  - Smart brute-force (prioritized, reduced charset based on your inputs)
  - Smart mutations from tokens (name, surname, city, birthdate, optional wordlist) with case/leet/suffix variations
- Live progress with ETA, sample preview, and cancel support
- Output to .txt or compressed .txt.gz
- Optional Pentest mode: send candidates to a target login URL via GET/POST with rate limiting, success/failure detection, and optional basic SQL injection probes (for authorized testing only)
- Save/Load profiles as JSON (legacy .pkl still loadable)
- Safety caps and warnings to avoid unbounded generation

## Install

- Python 3.9+
- Optional: ttkbootstrap for a modern theme

```bash
pip install -r requirements.txt
```

If you prefer not to install ttkbootstrap, the app will fall back to standard Tkinter ttk.

## Run

```bash
python SoupSalad.py
```

If you plan to use Pentest mode, install `requests`:

```bash
pip install requests
```

## Usage

1. Enter profile details (Name, Surname, City, Birthdate)
2. Choose a mode (Brute-force, Smart brute-force, or Smart mutations)
3. Set min/max lengths and optional special characters
4. Optional: enable Pentest, fill target URL, method (GET/POST), username value, form parameter names, success codes/regex, failure regex, and QPS. Optionally enable SQLi checks and choose which field to test first
5. If not using Pentest: choose an output file ("Browse…"). Enable "Gzip output" if desired
6. Click "Run" to start; use "Cancel" to stop
7. Preview/Log pane shows samples and request logs

Notes:
- Brute-force grows exponentially; the app warns/caps overly large runs
- Smart mutations uses tokens and realistic variations; it is more practical and smaller
- If a `wordlist.txt` is present in the working directory, up to 1000 words are included as extra tokens

## Profiles

- Save profiles to JSON using "Save Profile". Load them via "Load Profile"
- Legacy .pkl profiles from older versions can still be loaded

## License

MIT
