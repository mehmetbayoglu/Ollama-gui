#!/usr/bin/env python3
"""
Simple native desktop UI for the local Ollama server using Tkinter (built into Python).

Features:
- Refresh available models from the local Ollama API.
- Enter a prompt and stream the response into the window.
- Clear output and quick status updates.

Usage:
  python3 ollama_gui.py
Make sure your Ollama server is running locally (default: http://localhost:11434).
"""

import json
import queue
import re
import ssl
import threading
import tkinter as tk
from html import unescape
from pathlib import Path
from tkinter import messagebox, simpledialog
from urllib import error, parse, request

import ttkbootstrap as ttk
from ttkbootstrap.window import Window


DEFAULT_API_BASE = "http://localhost:11434"
CONFIG_PATH = Path.home() / ".ollama_gui.json"


class OllamaGUI(Window):
    def __init__(self) -> None:
        super().__init__(themename="darkly")
        self.title("Ollama Desktop UI")
        self.geometry("800x700")
        self.configure(bg="#1a0d15")  # Burgundy background

        # Configuration and state
        self.api_base = DEFAULT_API_BASE
        self.api_var = tk.StringVar(value=self.api_base)
        self.model_var = tk.StringVar(value="")
        self.session_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
        self.sessions: dict[str, str] = {}
        self.auto_search_var = tk.BooleanVar(value=False)
        # Queue used to marshal messages from worker threads back to the UI thread.
        self.ui_queue: queue.Queue[tuple[str, object]] = queue.Queue()

        self._load_config()
        self._setup_style()
        self._build_layout()
        self._start_queue_processor()
        self._refresh_models()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self) -> None:
        style = self.style
        # Use a platform-neutral base theme and override colors.
        accent = "#d24b86"  # lighter magenta accent
        muted = "#d3b7c5"
        bg = "#1a0d15"
        panel = "#24101c"
        text = "#f9eef6"

        base_font = ("Segoe UI", 11)
        mono_font = ("DejaVu Sans Mono", 10)
        self.option_add("*Font", base_font)

        style.configure(".", background=bg, foreground=text, fieldbackground=panel, bordercolor=panel)
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=text, bordercolor=panel, relief="flat", padding=8)
        style.configure("TLabelframe.Label", background=bg, foreground=muted)
        style.configure("TLabel", background=bg, foreground=text)
        style.configure("TEntry", fieldbackground=panel, foreground=text, bordercolor=panel, relief="flat")
        style.configure(
            "TCombobox",
            fieldbackground=panel,
            foreground=text,
            background=panel,
            bordercolor=panel,
            lightcolor=panel,
            darkcolor=panel,
            arrowsize=14,
            relief="flat",
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", panel)],
            foreground=[("readonly", text)],
            bordercolor=[("focus", accent)],
            lightcolor=[("focus", accent)],
        )
        style.configure(
            "TButton",
            background=panel,
            foreground=text,
            bordercolor=accent,
            focusthickness=1,
            relief="flat",
            padding=8,
        )
        style.map(
            "TButton",
            background=[("active", "#2c1523"), ("pressed", accent)],
            foreground=[("pressed", "#170914")],
            bordercolor=[("active", accent), ("pressed", accent)],
        )
        style.configure(
            "Accent.TButton",
            background=accent,
            foreground="#180910",
            bordercolor=accent,
            focusthickness=1,
            relief="flat",
            padding=8,
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#bb2c73"), ("pressed", "#a02565")],
            bordercolor=[("active", "#bb2c73"), ("pressed", "#a02565")],
        )
        style.configure(
            "AccentOutline.TButton",
            background=panel,
            foreground=accent,
            bordercolor=accent,
            focusthickness=1,
            relief="flat",
            padding=8,
        )
        style.map(
            "AccentOutline.TButton",
            background=[("active", "#2d1925"), ("pressed", "#2d1925")],
            bordercolor=[("active", accent), ("pressed", accent)],
            foreground=[("pressed", accent)],
        )
        style.configure("Status.TLabel", foreground=muted, background=bg)
        self._fonts = {"mono": mono_font}

    def _build_layout(self) -> None:
        padding = {"padx": 10, "pady": 6}

        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", **padding)

        ttk.Label(top_frame, text="Model:").pack(side="left")
        self.model_combo = ttk.Combobox(top_frame, textvariable=self.model_var, state="readonly", width=28)
        self.model_combo.pack(side="left", padx=6, ipady=2)

        ttk.Button(top_frame, text="Refresh Models", command=self._refresh_models, style="AccentOutline.TButton").pack(
            side="left"
        )

        ttk.Label(top_frame, text="API:").pack(side="left", padx=(18, 4))
        ttk.Entry(top_frame, textvariable=self.api_var, width=28).pack(side="left")
        ttk.Button(top_frame, text="Save API", command=self._update_api_base, bootstyle="secondary-outline").pack(
            side="left", padx=(6, 0)
        )

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, **padding)

        # Session list on the left
        session_frame = ttk.Labelframe(body, text="Sessions", width=180)
        session_frame.pack(side="left", fill="y", padx=(0, 10), pady=4)

        self.session_list = tk.Listbox(
            session_frame,
            height=8,
            bg="#24101c",
            fg="#f9eef6",
            selectbackground="#321624",
            selectforeground="#f9eef6",
            relief="flat",
            highlightthickness=0,
            borderwidth=0,
        )
        self.session_list.pack(fill="both", expand=True, padx=6, pady=6)
        self.session_list.bind("<<ListboxSelect>>", self._on_session_selected)

        session_buttons = ttk.Frame(session_frame)
        session_buttons.pack(fill="x", padx=6, pady=(0, 8))
        ttk.Button(session_buttons, text="New", command=self._new_session, bootstyle="success-outline").pack(
            side="left", expand=True, fill="x"
        )
        ttk.Button(session_buttons, text="Delete", command=self._delete_session, bootstyle="danger-outline").pack(
            side="left", expand=True, fill="x", padx=(6, 0)
        )

        # Main chat area
        chat_area = ttk.Frame(body)
        chat_area.pack(side="left", fill="both", expand=True)

        prompt_frame = ttk.Labelframe(chat_area, text="Prompt")
        prompt_frame.pack(fill="both", expand=False, pady=(0, 6))
        self.prompt_text = tk.Text(
            prompt_frame,
            height=8,
            wrap="word",
            bg="#24101c",
            fg="#f9eef6",
            insertbackground="#d24b86",
            relief="flat",
            font=self._fonts["mono"],
        )
        self.prompt_text.pack(fill="both", expand=True, padx=8, pady=8)

        controls_frame = ttk.Frame(chat_area)
        controls_frame.pack(fill="x", pady=(0, 6))
        ttk.Button(controls_frame, text="Generate", command=self._on_generate, style="Accent.TButton").pack(side="left")
        ttk.Button(controls_frame, text="Clear Output", command=self._clear_output, bootstyle="secondary").pack(
            side="left", padx=6
        )
        ttk.Checkbutton(
            controls_frame, text="Auto web search", variable=self.auto_search_var, bootstyle="round-toggle"
        ).pack(side="left", padx=10)

        status_label = ttk.Label(controls_frame, textvariable=self.status_var, style="Status.TLabel")
        status_label.pack(side="right")

        output_frame = ttk.Labelframe(chat_area, text="Response")
        output_frame.pack(fill="both", expand=True)
        self.output_text = tk.Text(
            output_frame,
            wrap="word",
            state="disabled",
            bg="#24101c",
            fg="#f9eef6",
            insertbackground="#d24b86",
            relief="flat",
            font=self._fonts["mono"],
        )
        self.output_text.pack(fill="both", expand=True, padx=8, pady=8)

        self._populate_sessions()

    def _start_queue_processor(self) -> None:
        self.after(100, self._process_queue)

    def _process_queue(self) -> None:
        while True:
            try:
                message_type, payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "models":
                self._update_models_ui(payload)
            elif message_type == "append":
                self._append_output(payload)
            elif message_type == "status":
                self.status_var.set(payload)
            elif message_type == "done":
                self._on_generation_finished(payload)

        # Keep processing messages regularly.
        self.after(100, self._process_queue)

    def _send_to_queue(self, message_type: str, payload: object) -> None:
        self.ui_queue.put((message_type, payload))

    def _refresh_models(self) -> None:
        self.status_var.set("Loading models...")
        threading.Thread(target=self._fetch_models_thread, args=(self.api_base,), daemon=True).start()

    def _fetch_models_thread(self, api_base: str) -> None:
        try:
            with request.urlopen(f"{api_base}/api/tags", timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
                self._send_to_queue("models", models)
                self._send_to_queue("status", f"Loaded {len(models)} models")
        except Exception as exc:  # Broad to show any connection issue
            self._send_to_queue("status", "Could not load models")
            message = f"Failed to load models from Ollama at {api_base}. Is the server running?\n\n{exc}"
            self._send_to_queue("append", f"\n[error] {message}\n")

    def _update_models_ui(self, models: list[str]) -> None:
        if not models:
            self.model_var.set("")
            self.model_combo["values"] = []
            return

        self.model_combo["values"] = models
        if self.model_var.get() not in models:
            self.model_var.set(models[0])

    def _on_generate(self) -> None:
        model = self.model_var.get().strip()
        prompt = self.prompt_text.get("1.0", "end").strip()

        if not model:
            messagebox.showwarning("Model required", "Please select a model.")
            return
        if not prompt:
            messagebox.showwarning("Prompt required", "Please enter a prompt.")
            return

        self.status_var.set(f"Generating with {model}...")
        self._autoname_session_from_prompt(prompt)
        threading.Thread(
            target=self._generate_with_optional_search, args=(model, prompt, self.api_base, self.auto_search_var.get()), daemon=True
        ).start()

    def _generate_with_optional_search(self, model: str, prompt: str, api_base: str, use_search: bool) -> None:
        combined_prompt = prompt
        if use_search:
            try:
                results = self._fetch_ddg_results(prompt)
                if results:
                    lines = ["[web search results]"]
                    for i, (title, url) in enumerate(results[:5], start=1):
                        lines.append(f"{i}. {title}\n{url}")
                    search_block = "\n".join(lines)
                    combined_prompt = f"{search_block}\n\n{prompt}"
                    self._send_to_queue("append", f"\n[using web search results]\n{search_block}\n\n")
                    self._send_to_queue("status", "Search results added to prompt")
                else:
                    self._send_to_queue("append", "\n[web] No results found; proceeding without search context.\n")
            except Exception as exc:
                self._send_to_queue("append", f"\n[web] Search failed: {exc}\nProceeding without search context.\n")
        self._append_output(f"\n[model: {model}]\n> {combined_prompt}\n\n")
        url = f"{api_base}/api/generate"
        payload = {"model": model, "prompt": combined_prompt, "stream": True}
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

        try:
            with request.urlopen(req, timeout=10) as resp:
                for raw_line in resp:
                    try:
                        line = raw_line.decode("utf-8").strip()
                        if not line:
                            continue
                        chunk = json.loads(line)
                        if "response" in chunk:
                            self._send_to_queue("append", chunk["response"])
                        if chunk.get("done"):
                            break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
            self._send_to_queue("done", None)
        except error.URLError as exc:
            self._send_to_queue("append", f"\n[error] Request failed: {exc}\n")
            self._send_to_queue("done", exc)
        except Exception as exc:  # Catch-all to avoid crashing the UI thread
            self._send_to_queue("append", f"\n[error] Unexpected error: {exc}\n")
            self._send_to_queue("done", exc)

    def _append_output(self, text: str) -> None:
        self.output_text.configure(state="normal")
        self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")
        self._stash_current_session_text()

    def _clear_output(self) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")
        self.status_var.set("Ready")
        self._stash_current_session_text()

    def _on_generation_finished(self, error_obj: object) -> None:
        if error_obj:
            self.status_var.set("Generation failed")
        else:
            self.status_var.set("Generation complete")

    def _parse_ddg_results(self, html: str) -> list[tuple[str, str]]:
        items: list[tuple[str, str]] = []
        # Extract anchors with result__a class.
        for href, title in re.findall(r'result__a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html):
            clean_title = unescape(re.sub("<.*?>", "", title)).strip()
            if not clean_title:
                continue
            normalized = self._normalize_ddg_link(unescape(href))
            items.append((clean_title, normalized))
            if len(items) >= 8:
                break
        return items

    def _normalize_ddg_link(self, href: str) -> str:
        # DuckDuckGo redirect links look like //duckduckgo.com/l/?uddg=<encoded>
        if "duckduckgo.com/l/?" in href:
            parsed = parse.urlparse(href)
            qs = parse.parse_qs(parsed.query)
            if "uddg" in qs and qs["uddg"]:
                return parse.unquote(qs["uddg"][0])
        # Add https if protocol-relative
        if href.startswith("//"):
            return "https:" + href
        return href

    def _fetch_ddg_results(self, query: str) -> list[tuple[str, str]]:
        q = parse.quote_plus(query)
        url = f"https://duckduckgo.com/html/?q={q}&kl=us-en"
        req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        # Use unverified context to avoid local MITM/self-signed failures.
        insecure_ctx = ssl._create_unverified_context()
        with request.urlopen(req, timeout=10, context=insecure_ctx) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        return self._parse_ddg_results(html)

    # ---------------------------
    # Session management & config
    # ---------------------------

    def _load_config(self) -> None:
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                self.api_base = data.get("api_base", DEFAULT_API_BASE)
                self.api_var.set(self.api_base)
                self.sessions = data.get("sessions", {})
                if not isinstance(self.sessions, dict):
                    self.sessions = {}
                self.session_var.set(data.get("active_session", ""))
            except Exception:
                self.api_base = DEFAULT_API_BASE
                self.sessions = {}

        if not self.sessions:
            self.sessions = {"Session 1": ""}
        if not self.session_var.get():
            self.session_var.set(next(iter(self.sessions.keys())))

    def _save_config(self) -> None:
        payload = {
            "api_base": self.api_base,
            "sessions": self.sessions,
            "active_session": self.session_var.get(),
        }
        try:
            CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            # Avoid crashing on save failure; best effort.
            pass

    def _populate_sessions(self) -> None:
        self.session_list.delete(0, "end")
        for name in self.sessions:
            self.session_list.insert("end", name)
        target = self.session_var.get()
        if target in self.sessions:
            idx = list(self.sessions.keys()).index(target)
            self.session_list.selection_set(idx)
            self.session_list.activate(idx)
            self._load_session_text(target)
        else:
            self.session_list.selection_set(0)
            self.session_var.set(self.session_list.get(0))
            self._load_session_text(self.session_var.get())

    def _on_session_selected(self, _: object) -> None:
        selection = self.session_list.curselection()
        if not selection:
            return
        new_session = self.session_list.get(selection[0])
        if new_session == self.session_var.get():
            return
        self._stash_current_session_text()
        self.session_var.set(new_session)
        self._load_session_text(new_session)
        self._save_config()

    def _stash_current_session_text(self) -> None:
        session_name = self.session_var.get()
        if not session_name:
            return
        text = self.output_text.get("1.0", "end")
        self.sessions[session_name] = text

    def _load_session_text(self, session_name: str) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", self.sessions.get(session_name, ""))
        self.output_text.configure(state="disabled")

    def _new_session(self) -> None:
        name = simpledialog.askstring("New Session", "Name for the session:", parent=self)
        if not name:
            return
        if name in self.sessions:
            messagebox.showinfo("Exists", "A session with that name already exists.")
            return
        self._stash_current_session_text()
        self.sessions[name] = ""
        self.session_var.set(name)
        self._populate_sessions()
        self._save_config()

    def _delete_session(self) -> None:
        if len(self.sessions) <= 1:
            messagebox.showinfo("Keep at least one", "You must have at least one session.")
            return
        selection = self.session_list.curselection()
        if not selection:
            return
        name = self.session_list.get(selection[0])
        if messagebox.askyesno("Delete Session", f"Delete '{name}'? This clears its history."):
            self.sessions.pop(name, None)
            # Pick another available session
            self.session_var.set(next(iter(self.sessions.keys())))
            self._populate_sessions()
            self._save_config()

    def _update_api_base(self) -> None:
        new_api = self.api_var.get().strip().rstrip("/")
        if not new_api:
            messagebox.showwarning("API required", "API URL cannot be empty.")
            return
        self.api_base = new_api
        self.status_var.set(f"API set to {self.api_base}")
        self._save_config()
        self._refresh_models()

    def _on_close(self) -> None:
        self._stash_current_session_text()
        self._save_config()
        self.destroy()

    def _autoname_session_from_prompt(self, prompt: str) -> None:
        """Rename the current session based on the first prompt if it's still a default name."""
        current = self.session_var.get()
        if not current:
            return
        existing_text = self.sessions.get(current, "")
        # Only rename if no prior content and the name looks like the default.
        if existing_text.strip():
            return
        if not current.lower().startswith("session"):
            return
        words = prompt.strip().split()
        if not words:
            return
        base_title = " ".join(words[:5])[:40].rstrip(".;,:-")
        if not base_title:
            return
        new_name = base_title
        suffix = 2
        while new_name in self.sessions:
            new_name = f"{base_title} ({suffix})"
            suffix += 1
        self.sessions[new_name] = self.sessions.pop(current, "")
        self.session_var.set(new_name)
        self._populate_sessions()
        self._save_config()


def main() -> None:
    app = OllamaGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
