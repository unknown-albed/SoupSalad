import os
import sys
import gzip
import json
import time
import math
import queue
import string
import threading
import itertools
from datetime import datetime

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext

# Try to use ttkbootstrap for a modern theme; fall back to standard ttk
try:
    import ttkbootstrap as tb
    from ttkbootstrap.dialogs import Messagebox as TbMessagebox
    from ttkbootstrap.constants import SUCCESS
    USE_TTKBOOTSTRAP = True
except Exception:
    USE_TTKBOOTSTRAP = False

from tkinter import ttk


class PasswordListGeneratorApp:
    def __init__(self) -> None:
        self.use_bootstrap = USE_TTKBOOTSTRAP
        if self.use_bootstrap:
            self.style = tb.Style(theme="cosmo")
            self.root = self.style.master
            self.root.title("Password List Generator")
        else:
            self.root = tk.Tk()
            self.root.title("Password List Generator")
        self.root.geometry("720x580")

        # State
        self.worker_thread: threading.Thread | None = None
        self.ui_queue: queue.Queue = queue.Queue()
        self.is_running = False
        self.cancel_requested = False
        self.generated_count = 0
        self.total_estimated = 0
        self.start_time: float | None = None

        # Variables
        self.var_name = tk.StringVar()
        self.var_surname = tk.StringVar()
        self.var_city = tk.StringVar()
        self.var_birthdate = tk.StringVar(value="1990")

        self.var_min_len = tk.IntVar(value=4)
        self.var_max_len = tk.IntVar(value=6)
        self.var_special_chars = tk.StringVar(value="!@#$%_-")

        self.var_mode = tk.StringVar(value="Brute-force")  # Brute-force | Smart mutations
        self.var_include_digits = tk.BooleanVar(value=True)
        self.var_include_uppercase = tk.BooleanVar(value=True)
        self.var_gzip = tk.BooleanVar(value=False)

        self.var_output_path = tk.StringVar(value=self._default_output_path())

        # Build UI
        self._build_ui()

        # Start UI queue processing
        self.root.after(100, self._process_ui_queue)

    def _default_output_path(self) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        base = f"Passwordlist-{timestamp}.txt"
        return os.path.join(os.getcwd(), base)

    def _build_ui(self) -> None:
        padding = {"padx": 8, "pady": 6}

        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        # Profile frame
        profile = ttk.LabelFrame(main, text="Profile")
        profile.pack(fill=tk.X, **padding)

        self._add_labeled_entry(profile, "Name", self.var_name, row=0, col=0)
        self._add_labeled_entry(profile, "Surname", self.var_surname, row=0, col=2)
        self._add_labeled_entry(profile, "City", self.var_city, row=1, col=0)
        self._add_labeled_entry(profile, "Birthdate (free text)", self.var_birthdate, row=1, col=2)

        # Generation options
        options = ttk.LabelFrame(main, text="Options")
        options.pack(fill=tk.X, **padding)

        # Mode
        ttk.Label(options, text="Mode").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        mode_combo = ttk.Combobox(options, textvariable=self.var_mode, values=["Brute-force", "Smart mutations"], state="readonly", width=18)
        mode_combo.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        # Lengths
        self._add_labeled_spinbox(options, "Min length", self.var_min_len, row=0, col=2, from_=1, to=16)
        self._add_labeled_spinbox(options, "Max length", self.var_max_len, row=0, col=4, from_=1, to=24)

        # Special chars
        self._add_labeled_entry(options, "Special chars", self.var_special_chars, row=1, col=0)

        # Flags
        ttk.Checkbutton(options, text="Include digits 0-9", variable=self.var_include_digits).grid(row=1, column=2, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(options, text="Include uppercase", variable=self.var_include_uppercase).grid(row=1, column=4, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(options, text="Gzip output (.gz)", variable=self.var_gzip).grid(row=1, column=5, sticky="w", padx=4, pady=4)

        for i in range(0, 6):
            options.grid_columnconfigure(i, weight=1)

        # Output selection
        out = ttk.LabelFrame(main, text="Output")
        out.pack(fill=tk.X, **padding)
        ttk.Label(out, text="File").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        entry = ttk.Entry(out, textvariable=self.var_output_path)
        entry.grid(row=0, column=1, sticky="we", padx=4, pady=4)
        browse = ttk.Button(out, text="Browse…", command=self._choose_output_file)
        browse.grid(row=0, column=2, sticky="w", padx=4, pady=4)
        out.grid_columnconfigure(1, weight=1)

        # Actions
        actions = ttk.Frame(main)
        actions.pack(fill=tk.X, **padding)
        self.btn_generate = ttk.Button(actions, text="Generate", command=self.on_generate)
        self.btn_generate.pack(side=tk.LEFT)
        self.btn_cancel = ttk.Button(actions, text="Cancel", command=self.on_cancel, state=tk.DISABLED)
        self.btn_cancel.pack(side=tk.LEFT, padx=8)
        self.btn_save = ttk.Button(actions, text="Save Profile", command=self.on_save_profile)
        self.btn_save.pack(side=tk.LEFT, padx=8)
        self.btn_load = ttk.Button(actions, text="Load Profile", command=self.on_load_profile)
        self.btn_load.pack(side=tk.LEFT, padx=8)

        # Progress
        progress_frame = ttk.Frame(main)
        progress_frame.pack(fill=tk.X, **padding)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=260, mode='determinate', variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X)
        self.status_var = tk.StringVar(value="Idle")
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        self.status_label.pack(anchor="w", pady=4)

        # Preview
        preview = ttk.LabelFrame(main, text="Preview (sample candidates)")
        preview.pack(fill=tk.BOTH, expand=True, **padding)
        self.preview_text = scrolledtext.ScrolledText(preview, height=12)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.configure(state=tk.DISABLED)

        # Footer note
        note = ttk.Label(main, text="Tip: Brute-force grows exponentially. Prefer Smart mutations for realistic lists.")
        note.pack(anchor="w", padx=10, pady=(0, 10))

    def _add_labeled_entry(self, master, label, var, row, col) -> None:
        ttk.Label(master, text=label).grid(row=row, column=col, sticky="e", padx=4, pady=4)
        entry = ttk.Entry(master, textvariable=var, width=24)
        entry.grid(row=row, column=col + 1, sticky="w", padx=4, pady=4)

    def _add_labeled_spinbox(self, master, label, var, row, col, from_, to) -> None:
        ttk.Label(master, text=label).grid(row=row, column=col, sticky="e", padx=4, pady=4)
        spin = ttk.Spinbox(master, textvariable=var, from_=from_, to=to, width=6)
        spin.grid(row=row, column=col + 1, sticky="w", padx=4, pady=4)

    def _choose_output_file(self) -> None:
        default = self.var_output_path.get() or self._default_output_path()
        initialdir = os.path.dirname(default) if os.path.dirname(default) else os.getcwd()
        def_ext = ".txt.gz" if self.var_gzip.get() else ".txt"
        filetypes = [("Gzip text", "*.txt.gz"), ("Text", "*.txt"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(initialdir=initialdir, initialfile=os.path.basename(default), defaultextension=def_ext, filetypes=filetypes)
        if path:
            self.var_output_path.set(path)

    def _process_ui_queue(self) -> None:
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if item[0] == "progress":
                    _, completed, total, elapsed = item
                    percent = (completed / total * 100.0) if total > 0 else 0.0
                    self.progress_var.set(percent)
                    eta = (elapsed / completed * (total - completed)) if completed > 0 else 0.0
                    self.status_var.set(f"Generated: {completed:,}/{total:,}  |  {percent:0.2f}%  |  Elapsed: {self._fmt_sec(elapsed)}  |  ETA: {self._fmt_sec(eta)}")
                elif item[0] == "sample":
                    _, sample = item
                    self._append_preview(sample)
                elif item[0] == "done":
                    _, completed = item
                    self._on_done(completed)
                elif item[0] == "message":
                    _, msg = item
                    self.status_var.set(msg)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_ui_queue)

    def _append_preview(self, line: str) -> None:
        self.preview_text.configure(state=tk.NORMAL)
        self.preview_text.insert(tk.END, line + "\n")
        # Limit preview size
        if float(self.preview_text.index('end-1c').split('.')[0]) > 5000:
            self.preview_text.delete('1.0', '2.0')
        self.preview_text.see(tk.END)
        self.preview_text.configure(state=tk.DISABLED)

    def _on_done(self, completed: int) -> None:
        self.is_running = False
        self.cancel_requested = False
        self.btn_generate.configure(state=tk.NORMAL)
        self.btn_cancel.configure(state=tk.DISABLED)
        self.progress_var.set(100.0)
        msg = f"Completed. Generated {completed:,} candidates. Saved to: {self.var_output_path.get()}"
        self.status_var.set(msg)
        if self.use_bootstrap:
            TbMessagebox.show_info("Done", msg)
        else:
            messagebox.showinfo("Done", msg)

    def _fmt_sec(self, seconds: float) -> str:
        seconds = max(0.0, float(seconds))
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h {m}m {s}s"
        if m > 0:
            return f"{m}m {s}s"
        return f"{s}s"

    def on_generate(self) -> None:
        if self.is_running:
            return

        try:
            min_len = int(self.var_min_len.get())
            max_len = int(self.var_max_len.get())
            if min_len <= 0 or max_len <= 0 or max_len < min_len:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid lengths", "Please provide valid positive min/max lengths (max >= min).")
            return

        output_path = self.var_output_path.get().strip()
        if not output_path:
            messagebox.showerror("Output file", "Please choose an output file path.")
            return

        # Ensure extension matches gzip choice
        if self.var_gzip.get() and not output_path.endswith(".gz"):
            output_path += ".gz"
            self.var_output_path.set(output_path)
        if not self.var_gzip.get() and output_path.endswith(".gz"):
            # allow gz extension without gzip if user insists, but we will still write gzip when checkbox ticked
            pass

        # Estimate total candidates and ask for confirmation if too large
        mode = self.var_mode.get()
        total_est = 0
        if mode == "Brute-force":
            char_set = self._build_bruteforce_charset()
            n = len(char_set)
            if n <= 0:
                messagebox.showerror("Character set", "Character set is empty. Provide inputs or special characters.")
                return
            total_est = self._geom_series(n, min_len, max_len)
        else:
            total_est = self._estimate_smart_total(min_len, max_len)

        HARD_CAP = 25_000_000  # hard safety cap
        WARN_CAP = 5_000_000   # warn threshold
        if total_est > HARD_CAP and mode == "Brute-force":
            messagebox.showwarning("Too large", f"Estimated {total_est:,} candidates which exceeds the hard cap of {HARD_CAP:,}. Reduce lengths or character set.")
            return
        if total_est > WARN_CAP:
            proceed = messagebox.askyesno("Large generation", f"Estimated to generate about {total_est:,} candidates. This may take a long time and large disk space. Continue?")
            if not proceed:
                return

        # Prepare UI
        self.preview_text.configure(state=tk.NORMAL)
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.configure(state=tk.DISABLED)
        self.progress_var.set(0.0)
        self.status_var.set("Starting…")
        self.generated_count = 0
        self.total_estimated = total_est
        self.start_time = time.time()

        # Start worker
        self.is_running = True
        self.cancel_requested = False
        self.btn_generate.configure(state=tk.DISABLED)
        self.btn_cancel.configure(state=tk.NORMAL)

        args = {
            "mode": mode,
            "min_len": min_len,
            "max_len": max_len,
            "gzip": self.var_gzip.get(),
            "output_path": output_path,
        }
        self.worker_thread = threading.Thread(target=self._worker, args=(args,), daemon=True)
        self.worker_thread.start()

    def on_cancel(self) -> None:
        if not self.is_running:
            return
        self.cancel_requested = True
        self.status_var.set("Canceling…")

    def on_save_profile(self) -> None:
        profile = {
            "name": self.var_name.get(),
            "surname": self.var_surname.get(),
            "city": self.var_city.get(),
            "birthdate": self.var_birthdate.get(),
            "min_len": self.var_min_len.get(),
            "max_len": self.var_max_len.get(),
            "special_chars": self.var_special_chars.get(),
            "include_digits": self.var_include_digits.get(),
            "include_uppercase": self.var_include_uppercase.get(),
            "mode": self.var_mode.get(),
            "gzip": self.var_gzip.get(),
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Profile JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        self._info("Profile saved")

    def on_load_profile(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Profile JSON", "*.json"), ("Legacy pickle", "*.pkl"), ("All files", "*.*")])
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    profile = json.load(f)
            else:
                # Legacy: try pickle
                import pickle
                with open(path, "rb") as f:
                    profile = pickle.load(f)
        except Exception as exc:
            messagebox.showerror("Load failed", f"Could not load profile: {exc}")
            return

        # Map fields
        self.var_name.set(profile.get("name", ""))
        self.var_surname.set(profile.get("surname", ""))
        self.var_city.set(profile.get("city", ""))
        self.var_birthdate.set(profile.get("birthdate", ""))
        self.var_min_len.set(int(profile.get("min_len", 4)))
        self.var_max_len.set(int(profile.get("max_len", 6)))
        self.var_special_chars.set(profile.get("special_chars", "!@#$%_-"))
        self.var_include_digits.set(bool(profile.get("include_digits", True)))
        self.var_include_uppercase.set(bool(profile.get("include_uppercase", True)))
        self.var_mode.set(profile.get("mode", "Brute-force"))
        self.var_gzip.set(bool(profile.get("gzip", False)))
        self._info("Profile loaded")

    def _info(self, msg: str) -> None:
        self.status_var.set(msg)
        if self.use_bootstrap:
            TbMessagebox.show_info("Info", msg)
        else:
            messagebox.showinfo("Info", msg)

    def _build_bruteforce_charset(self) -> str:
        combined = (
            self.var_name.get() + self.var_surname.get() + self.var_city.get() + self.var_birthdate.get()
        )
        # unique characters preserving order
        seen = set()
        unique_chars = ''.join([c for c in combined if not (c in seen or seen.add(c))])
        if self.var_include_uppercase.get():
            unique_chars += ''.join({c.upper() for c in unique_chars if c.isalpha()})
        if self.var_include_digits.get():
            unique_chars += string.digits
        special = self.var_special_chars.get() or ""
        charset = ''.join(sorted(set(unique_chars + special)))
        return charset

    def _estimate_smart_total(self, min_len: int, max_len: int) -> int:
        # Rough, safe estimate for smart mode (tokens, mutations, small suffix set)
        tokens = self._smart_tokens()
        base = len(tokens)
        variants_per_token = 6  # case + leet variations approximation
        suffixes = 40  # numbers, specials, simple years
        combos = 0
        # token only
        combos += base * variants_per_token
        # token + suffix
        combos += base * variants_per_token * suffixes
        # token pairs (limited)
        combos += min(base * base, 2000) * variants_per_token
        # Respect length bounds approximately by assuming half filtered out
        combos = int(combos * 0.5)
        # Then clip by theoretical length window
        return max(1000, min(combos, 5_000_000))

    def _geom_series(self, n: int, a: int, b: int) -> int:
        # sum_{L=a..b} n^L
        if n == 1:
            return b - a + 1
        return (n ** (b + 1) - n ** a) // (n - 1)

    def _worker(self, args: dict) -> None:
        mode = args["mode"]
        min_len = args["min_len"]
        max_len = args["max_len"]
        gzip_out = args["gzip"]
        output_path = args["output_path"]

        # Open output file
        try:
            if gzip_out:
                f = gzip.open(output_path, "wt", encoding="utf-8")
            else:
                f = open(output_path, "w", encoding="utf-8")
        except Exception as exc:
            self.ui_queue.put(("message", f"Failed to open output file: {exc}"))
            self.ui_queue.put(("done", 0))
            return

        completed = 0
        sample_sent = 0
        start = self.start_time or time.time()

        try:
            if mode == "Brute-force":
                charset = self._build_bruteforce_charset()
                total = self._geom_series(len(charset), min_len, max_len)
                self.total_estimated = total
                for L in range(min_len, max_len + 1):
                    if self.cancel_requested:
                        break
                    for tup in itertools.product(charset, repeat=L):
                        if self.cancel_requested:
                            break
                        pwd = ''.join(tup)
                        f.write(pwd + "\n")
                        completed += 1
                        if sample_sent < 50:
                            self.ui_queue.put(("sample", pwd))
                            sample_sent += 1
                        if completed % 5000 == 0:
                            elapsed = time.time() - start
                            self.ui_queue.put(("progress", completed, self.total_estimated, elapsed))
            else:
                # Smart mutations
                for pwd in self._smart_candidates(min_len, max_len):
                    if self.cancel_requested:
                        break
                    f.write(pwd + "\n")
                    completed += 1
                    if sample_sent < 50:
                        self.ui_queue.put(("sample", pwd))
                        sample_sent += 1
                    if completed % 5000 == 0:
                        elapsed = time.time() - start
                        self.ui_queue.put(("progress", completed, max(self.total_estimated, completed), elapsed))
        finally:
            try:
                f.close()
            except Exception:
                pass

        self.ui_queue.put(("progress", completed, max(self.total_estimated, completed), time.time() - start))
        self.ui_queue.put(("done", completed))

    def _smart_tokens(self) -> list[str]:
        tokens: list[str] = []
        base_parts = [self.var_name.get(), self.var_surname.get(), self.var_city.get(), self.var_birthdate.get()]
        for part in base_parts:
            part = (part or "").strip()
            if not part:
                continue
            # split on common separators
            for t in filter(None, itertools.chain.from_iterable([p.split(sep) for sep in [" ", "-", "_", ".", ",", "/"] for p in [part]])):
                tokens.append(t)
                # numbers within birthdate (extract plausible year fragments)
                if t.isdigit() and 2 <= len(t) <= 4:
                    tokens.append(t)
        # Read optional wordlist.txt if exists
        wordlist_path = os.path.join(os.getcwd(), "wordlist.txt")
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wf:
                    for i, line in enumerate(wf):
                        if i >= 1000:  # limit to keep sane
                            break
                        w = line.strip()
                        if w:
                            tokens.append(w)
            except Exception:
                pass
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for t in tokens:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        return deduped[:2000]

    def _mutate_cases_and_leet(self, token: str) -> list[str]:
        variants = set()
        if not token:
            return []
        s = token
        variants.add(s)
        variants.add(s.lower())
        variants.add(s.upper())
        variants.add(s.capitalize())
        # simple leet
        leet_map = str.maketrans({"a": "@", "A": "@", "e": "3", "E": "3", "i": "1", "I": "1", "o": "0", "O": "0", "s": "5", "S": "5"})
        variants.add(s.translate(leet_map))
        variants.add(s.lower().translate(leet_map))
        return [v for v in variants if v]

    def _smart_candidates(self, min_len: int, max_len: int):
        # Generator yielding reasonably sized candidate set using tokens, mutations, and suffixes
        specials = list(self.var_special_chars.get() or "")
        digits = list(string.digits) if self.var_include_digits.get() else []
        years = [str(y) for y in range(1970, datetime.now().year + 1)]
        simple_suffixes = ["", "!", "?", ".", "_", "-", "#"]

        tokens = self._smart_tokens()
        variants_cache: dict[str, list[str]] = {}

        def within_bounds(pw: str) -> bool:
            return min_len <= len(pw) <= max_len

        emitted = set()
        count = 0
        limit = 5_000_000

        # Single token variants and suffixes
        for t in tokens:
            if count >= limit:
                break
            variants = variants_cache.setdefault(t, self._mutate_cases_and_leet(t))
            for v in variants:
                if count >= limit:
                    break
                # bare variant
                if within_bounds(v) and v not in emitted:
                    emitted.add(v); count += 1; yield v
                # variant + simple suffix
                for suf in itertools.chain(simple_suffixes, specials):
                    if count >= limit:
                        break
                    pw = v + suf
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw
                # variant + number suffix
                for n in range(0, 100):
                    if count >= limit:
                        break
                    pw = f"{v}{n}"
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw
                # variant + year
                for y in years[-50:]:  # last 50 years
                    if count >= limit:
                        break
                    pw = f"{v}{y}"
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw

        # Token pairs
        for a, b in itertools.islice(itertools.product(tokens, tokens), 0, 2000):
            if count >= limit:
                break
            for av in variants_cache.setdefault(a, self._mutate_cases_and_leet(a)):
                for bv in variants_cache.setdefault(b, self._mutate_cases_and_leet(b)):
                    if count >= limit:
                        break
                    pw = av + bv
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw
                    # with splitter
                    for sep in itertools.chain(["", "_", "-", "."], specials):
                        if count >= limit:
                            break
                        pw2 = av + sep + bv
                        if within_bounds(pw2) and pw2 not in emitted:
                            emitted.add(pw2); count += 1; yield pw2

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    app = PasswordListGeneratorApp()
    app.run()
