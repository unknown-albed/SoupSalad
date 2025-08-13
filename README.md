# SoupSalad

A modernized, GUI-based Password List Generator built with Python. Generate custom password dictionaries from profile data using either character brute-force or realistic smart mutations.

## Highlights

- Modern themed UI (uses ttkbootstrap when available)
- Two generation modes:
  - Brute-force over a chosen character set and length range
  - Smart mutations from tokens (name, surname, city, birthdate, optional wordlist) with case/leet/suffix variations
- Live progress with ETA, sample preview, and cancel support
- Output to .txt or compressed .txt.gz
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

## Usage

1. Enter profile details (Name, Surname, City, Birthdate)
2. Choose a mode (Brute-force or Smart mutations)
3. Set min/max lengths and optional special characters
4. Choose an output file ("Browse…"). Enable "Gzip output" if desired
5. Click "Generate" to start; use "Cancel" to stop
6. Preview window shows sample candidates

Notes:
- Brute-force grows exponentially; the app warns/caps overly large runs
- Smart mutations uses tokens and realistic variations; it is more practical and smaller
- If a `wordlist.txt` is present in the working directory, up to 1000 words are included as extra tokens

## Profiles

- Save profiles to JSON using "Save Profile". Load them via "Load Profile"
- Legacy .pkl profiles from older versions can still be loaded

## License

MIT
