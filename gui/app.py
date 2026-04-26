"""
Tkinter GUI for the Hash Verification Tool.

Design notes
------------
* Thin layer on top of core/ — all hashing / manifest / reporting logic
  stays in the core package unchanged.
* Long-running work runs on a daemon thread. A small queue hands
  progress / done / error messages back to the Tk main loop via
  ``after()`` polling so the UI never freezes.
* Language is switchable at runtime (Settings → Language). The choice
  is persisted to a JSON settings file next to the script / exe.
"""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable, Optional

from core import __version__
from core.hash_utils import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    ProgressEvent,
    compute_file_hash,
)
from core.manifest_manager import (
    Manifest,
    build_manifest_for_file,
    build_manifest_for_folder,
)
from core.reporter import convert_report, report_to_csv, report_to_json
from core.verifier import Verifier
from gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    get_language,
    set_language,
    t,
)
from utils.logger import get_logger
from utils.settings import load_settings, save_settings

log = get_logger("gui")

POLL_INTERVAL_MS = 100

# Tag → foreground colour for the verification result tree.
STATUS_COLORS = {
    "unchanged": "#2e7d32",   # green
    "modified":  "#e65100",   # orange
    "new":       "#1565c0",   # blue
    "missing":   "#c62828",   # red
    "errors":    "#6a1b9a",   # purple
}

# Max visible path length in the status bar before we truncate with an
# ellipsis prefix. Keeps the bar from reflowing on very deep trees.
_STATUS_PATH_MAX = 60


def _shorten(path: str, limit: int = _STATUS_PATH_MAX) -> str:
    if len(path) <= limit:
        return path
    return "…" + path[-(limit - 1):]


# ======================================================================
# Worker thread
# ======================================================================
@dataclass
class _Message:
    kind: str       # "done" | "error"
    payload: Any


class _Worker:
    """
    Run a callable on a daemon thread and expose results via a queue.

    The *target* receives a single ``emit`` callback so it can push
    progress updates back to the UI thread (e.g. ``emit(_Message(
    "progress", event))``). The worker itself enqueues the terminal
    ``"done"`` / ``"error"`` messages once *target* returns / raises.
    """

    def __init__(self, target: Callable[[Callable[["_Message"], None]], Any]) -> None:
        self._queue: "queue.Queue[_Message]" = queue.Queue()
        self._target = target
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def drain(self) -> list["_Message"]:
        out: list[_Message] = []
        try:
            while True:
                out.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        return out

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _emit(self, msg: "_Message") -> None:
        self._queue.put(msg)

    def _run(self) -> None:
        try:
            result = self._target(self._emit)
            self._queue.put(_Message("done", result))
        except Exception as exc:
            log.exception("worker failed")
            self._queue.put(_Message("error", exc))


# ======================================================================
# Main application window
# ======================================================================
class HashToolApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        # Load language preference *before* building any widgets.
        self._settings = load_settings()
        set_language(self._settings.get("language", DEFAULT_LANGUAGE))

        self.geometry("940x700")
        self.minsize(780, 560)
        self._apply_style()

        self._menubar: Optional[tk.Menu] = None
        self.notebook: Optional[ttk.Notebook] = None
        self._statusbar: Optional[ttk.Frame] = None
        self.status_var = tk.StringVar(value=t("status.ready"))
        self._worker: Optional[_Worker] = None

        self._render_ui()

    # ------------------------------------------------------------------
    # Chrome
    # ------------------------------------------------------------------
    def _apply_style(self) -> None:
        style = ttk.Style(self)
        for theme in ("vista", "clam", "default"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue
        style.configure("Status.TLabel", padding=(8, 4))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _render_ui(self) -> None:
        """Build window title, menu, notebook and status bar from scratch."""
        self.title(f"{t('app.title')}  —  v{__version__}")
        self._build_menu()
        self._build_notebook()
        self._build_statusbar()
        self.status_var.set(t("status.ready"))

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        filemenu = tk.Menu(menubar, tearoff=False)
        filemenu.add_command(label=t("menu.exit"), command=self.destroy)
        menubar.add_cascade(label=t("menu.file"), menu=filemenu)

        settingsmenu = tk.Menu(menubar, tearoff=False)
        langmenu = tk.Menu(settingsmenu, tearoff=False)
        current = get_language()
        for code in SUPPORTED_LANGUAGES:
            prefix = "• " if code == current else "  "
            langmenu.add_command(
                label=prefix + t(f"menu.language.{code}"),
                command=lambda c=code: self._switch_language(c),
            )
        settingsmenu.add_cascade(label=t("menu.language"), menu=langmenu)
        menubar.add_cascade(label=t("menu.settings"), menu=settingsmenu)

        helpmenu = tk.Menu(menubar, tearoff=False)
        helpmenu.add_command(label=t("menu.about"), command=self._show_about)
        menubar.add_cascade(label=t("menu.help"), menu=helpmenu)

        self.config(menu=menubar)
        self._menubar = menubar

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(10, 0))

        self.hash_tab = HashTab(nb, self)
        self.verify_tab = VerifyTab(nb, self)
        self.report_tab = ReportTab(nb, self)

        nb.add(self.hash_tab,   text=t("tab.hash"))
        nb.add(self.verify_tab, text=t("tab.verify"))
        nb.add(self.report_tab, text=t("tab.report"))

        self.notebook = nb

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel", anchor="w").pack(
            side="left", fill="x", expand=True
        )
        # Determinate by default so we can display an actual percentage
        # as soon as the worker starts emitting ProgressEvents.
        self.progress = ttk.Progressbar(bar, mode="determinate", length=200, maximum=100)
        self.progress.pack(side="right", padx=8, pady=4)
        self._statusbar = bar

    # ------------------------------------------------------------------
    # Language switching — tear down chrome, rebuild in the new locale.
    # ------------------------------------------------------------------
    def _switch_language(self, lang: str) -> None:
        if lang == get_language():
            return
        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo(t("status.busy_title"), t("status.busy_body"))
            return

        set_language(lang)
        self._settings["language"] = lang
        save_settings(self._settings)

        # Capture which tab was active so the user doesn't lose context.
        active = 0
        if self.notebook is not None:
            try:
                active = self.notebook.index(self.notebook.select())
            except tk.TclError:
                active = 0

        if self._menubar is not None:
            self._menubar.destroy()
            self._menubar = None
        if self.notebook is not None:
            self.notebook.destroy()
            self.notebook = None
        if self._statusbar is not None:
            self._statusbar.destroy()
            self._statusbar = None

        self._render_ui()

        if self.notebook is not None:
            try:
                self.notebook.select(active)
            except tk.TclError:
                pass

    # ------------------------------------------------------------------
    # Background-work plumbing
    # ------------------------------------------------------------------
    def run_async(
        self,
        target: Callable[[Callable[["_Message"], None]], Any],
        *,
        status: str,
        on_done: Callable[[Any], None],
        on_error: Optional[Callable[[Exception], None]] = None,
        on_progress: Optional[Callable[[ProgressEvent], None]] = None,
    ) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo(t("status.busy_title"), t("status.busy_body"))
            return

        self.status_var.set(status)
        self.progress.configure(mode="determinate", maximum=100)
        self.progress["value"] = 0
        self._worker = _Worker(target)
        self._worker.start()
        self.after(POLL_INTERVAL_MS, self._poll, on_done, on_error, on_progress)

    def _poll(
        self,
        on_done: Callable[[Any], None],
        on_error: Optional[Callable[[Exception], None]],
        on_progress: Optional[Callable[[ProgressEvent], None]],
    ) -> None:
        worker = self._worker
        if worker is None:
            return
        for msg in worker.drain():
            if msg.kind == "progress":
                event: ProgressEvent = msg.payload
                self.progress["value"] = event.percent
                if on_progress is not None:
                    on_progress(event)
                continue
            if msg.kind == "done":
                self.progress["value"] = 100
                self._finish(t("status.ready"))
                on_done(msg.payload)
                return
            if msg.kind == "error":
                self._finish(t("status.error"))
                if on_error:
                    on_error(msg.payload)
                else:
                    messagebox.showerror(t("status.error"), str(msg.payload))
                return
        if worker.is_alive():
            self.after(POLL_INTERVAL_MS, self._poll, on_done, on_error, on_progress)
        else:
            self._finish(t("status.ready"))

    def _finish(self, status: str) -> None:
        self.progress["value"] = 0
        self.status_var.set(status)
        self._worker = None

    # ------------------------------------------------------------------
    def _show_about(self) -> None:
        messagebox.showinfo(
            t("about.title"),
            t("about.body", version=__version__),
        )


# ======================================================================
# Shared tab helpers
# ======================================================================
class _BaseTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, app: HashToolApp) -> None:
        super().__init__(parent, padding=16)
        self.app = app
        self._build()

    def _build(self) -> None:  # overridden
        raise NotImplementedError

    def _path_row(
        self,
        row: int,
        label: str,
        variable: tk.StringVar,
        pick_callback: Callable[[], None],
    ) -> None:
        ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=variable, width=70).grid(
            row=row, column=1, sticky="ew", padx=(6, 6), pady=4
        )
        ttk.Button(self, text=t("btn.browse"), command=pick_callback).grid(
            row=row, column=2, sticky="e", pady=4
        )


# ======================================================================
# Tab 1 — Hash generation
# ======================================================================
class HashTab(_BaseTab):
    def _build(self) -> None:
        self.columnconfigure(1, weight=1)

        self.mode_var = tk.StringVar(value="folder")
        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        ttk.Label(mode_frame, text=t("hash.target")).pack(side="left", padx=(0, 10))
        ttk.Radiobutton(
            mode_frame, text=t("hash.mode.file"), value="file", variable=self.mode_var
        ).pack(side="left")
        ttk.Radiobutton(
            mode_frame, text=t("hash.mode.folder"), value="folder", variable=self.mode_var
        ).pack(side="left", padx=(10, 0))

        self.target_var = tk.StringVar()
        self._path_row(1, t("hash.path"), self.target_var, self._pick_target)

        ttk.Label(self, text=t("hash.algorithm")).grid(row=2, column=0, sticky="w", pady=4)
        self.algo_var = tk.StringVar(value=DEFAULT_ALGORITHM)
        ttk.Combobox(
            self,
            textvariable=self.algo_var,
            values=list(SUPPORTED_ALGORITHMS),
            state="readonly",
            width=20,
        ).grid(row=2, column=1, sticky="w", padx=(6, 0), pady=4)

        self.output_var = tk.StringVar()
        self._path_row(3, t("hash.output"), self.output_var, self._pick_output)

        ttk.Button(
            self, text=t("hash.btn"), command=self._on_run, style="Accent.TButton"
        ).grid(row=4, column=0, columnspan=3, sticky="e", pady=(12, 8))

        ttk.Label(self, text=t("hash.result")).grid(row=5, column=0, sticky="w")
        self.output_area = ScrolledText(self, height=18, wrap="word", font=("Consolas", 10))
        self.output_area.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        self.rowconfigure(6, weight=1)

    def _pick_target(self) -> None:
        if self.mode_var.get() == "file":
            path = filedialog.askopenfilename(title=t("hash.picker.file_title"))
        else:
            path = filedialog.askdirectory(title=t("hash.picker.folder_title"))
        if path:
            self.target_var.set(path)

    def _pick_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title=t("hash.picker.save_title"),
            defaultextension=".json",
            filetypes=[("JSON manifest", "*.json"), ("All files", "*.*")],
            initialfile="manifest.json",
        )
        if path:
            self.output_var.set(path)

    def _on_run(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning(t("hash.missing_title"), t("hash.missing_body"))
            return

        algo = self.algo_var.get()
        output = self.output_var.get().strip() or None
        mode = self.mode_var.get()

        self._append(t("hash.log.header", mode=mode, algo=algo, target=target))

        def work(emit: Callable[[_Message], None]) -> dict[str, Any]:
            if mode == "file":
                digest = compute_file_hash(target, algorithm=algo)
                saved = None
                if output:
                    build_manifest_for_file(target, algorithm=algo).save(output)
                    saved = output
                emit(_Message("progress", ProgressEvent(done=1, total=1, path=target)))
                return {"mode": "file", "digest": digest, "output": saved}

            def on_progress(event: ProgressEvent) -> None:
                emit(_Message("progress", event))

            manifest = build_manifest_for_folder(
                target, algorithm=algo, on_progress=on_progress
            )
            saved_to = output or str(Path(target).with_name("manifest.json"))
            manifest.save(saved_to)
            return {
                "mode": "folder",
                "count": len(manifest.entries),
                "output": saved_to,
            }

        def show_progress(event: ProgressEvent) -> None:
            self.app.status_var.set(
                t("hash.progress", done=event.done, total=event.total,
                  path=_shorten(event.path))
            )

        self.app.run_async(
            work,
            status=t("hash.status", mode=mode),
            on_done=self._on_done,
            on_error=lambda exc: messagebox.showerror(t("hash.err_title"), str(exc)),
            on_progress=show_progress,
        )

    def _on_done(self, result: dict[str, Any]) -> None:
        if result["mode"] == "file":
            self._append(t("hash.log.digest", digest=result["digest"]))
            if result["output"]:
                self._append(t("hash.log.saved", path=result["output"]))
        else:
            self._append(t("hash.log.count", count=result["count"]))
            self._append(t("hash.log.saved", path=result["output"]))
        self._append(t("hash.log.done"))

    def _append(self, text: str) -> None:
        self.output_area.insert("end", text)
        self.output_area.see("end")


# ======================================================================
# Tab 2 — Verify
# ======================================================================
class VerifyTab(_BaseTab):
    def _build(self) -> None:
        self.columnconfigure(1, weight=1)

        self.folder_var = tk.StringVar()
        self._path_row(0, t("verify.folder"), self.folder_var, self._pick_folder)

        self.manifest_var = tk.StringVar()
        self._path_row(1, t("verify.manifest"), self.manifest_var, self._pick_manifest)

        self.report_var = tk.StringVar()
        self._path_row(2, t("verify.report"), self.report_var, self._pick_report)

        ttk.Button(
            self, text=t("verify.btn"), command=self._on_run, style="Accent.TButton"
        ).grid(row=3, column=0, columnspan=3, sticky="e", pady=(12, 8))

        ttk.Label(self, text=t("verify.summary")).grid(row=4, column=0, sticky="w")
        self.summary = ScrolledText(self, height=7, wrap="word", font=("Consolas", 10))
        self.summary.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(4, 6))

        ttk.Label(self, text=t("verify.details")).grid(row=6, column=0, sticky="w")
        self.tree = ttk.Treeview(
            self, columns=("status", "path"), show="headings", height=14
        )
        self.tree.heading("status", text=t("verify.col.status"))
        self.tree.heading("path", text=t("verify.col.path"))
        self.tree.column("status", width=130, anchor="w", stretch=False)
        self.tree.column("path", anchor="w")
        self.tree.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        for tag, color in STATUS_COLORS.items():
            self.tree.tag_configure(tag, foreground=color)
        self.rowconfigure(7, weight=1)

    def _pick_folder(self) -> None:
        path = filedialog.askdirectory(title=t("verify.picker.folder_title"))
        if path:
            self.folder_var.set(path)

    def _pick_manifest(self) -> None:
        path = filedialog.askopenfilename(
            title=t("verify.picker.manifest_title"),
            filetypes=[("JSON manifest", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.manifest_var.set(path)

    def _pick_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title=t("verify.picker.report_title"),
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")],
            initialfile="report.json",
        )
        if path:
            self.report_var.set(path)

    def _on_run(self) -> None:
        folder = self.folder_var.get().strip()
        manifest_path = self.manifest_var.get().strip()
        if not folder or not manifest_path:
            messagebox.showwarning(t("verify.missing_title"), t("verify.missing_body"))
            return

        self.summary.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.summary.insert("end", t("verify.running") + "\n")

        report_path = self.report_var.get().strip() or None

        def work(emit: Callable[[_Message], None]) -> dict:
            manifest = Manifest.load(manifest_path)

            def on_progress(event: ProgressEvent) -> None:
                emit(_Message("progress", event))

            result = Verifier(manifest).verify(folder, on_progress=on_progress)
            saved_to = None
            if report_path:
                if report_path.lower().endswith(".csv"):
                    report_to_csv(result, report_path)
                else:
                    report_to_json(result, report_path)
                saved_to = report_path
            return {"result": result, "saved_to": saved_to}

        def show_progress(event: ProgressEvent) -> None:
            self.app.status_var.set(
                t("verify.progress", done=event.done, total=event.total,
                  path=_shorten(event.path))
            )

        self.app.run_async(
            work,
            status=t("verify.running"),
            on_done=self._on_done,
            on_error=lambda exc: messagebox.showerror(t("verify.err_title"), str(exc)),
            on_progress=show_progress,
        )

    def _on_done(self, payload: dict) -> None:
        result = payload["result"]
        saved_to = payload["saved_to"]
        summary = result.summary()
        self.summary.delete("1.0", "end")
        self.summary.insert("end", t("verify.log.folder", folder=result.folder))
        self.summary.insert("end", t("verify.log.algorithm", algorithm=result.algorithm))
        for key in ("total_scanned", "unchanged", "modified", "new", "missing", "errors"):
            label = t(f"verify.summary.{key}")
            self.summary.insert("end", f"  {label:<18}: {summary[key]}\n")
        self.summary.insert(
            "end",
            "\n" + (t("verify.result.clean") if result.is_clean else t("verify.result.dirty")) + "\n",
        )
        if saved_to:
            self.summary.insert("end", t("verify.log.report_saved", path=saved_to))

        status_labels = {
            "unchanged": t("verify.summary.unchanged"),
            "modified":  t("verify.summary.modified"),
            "new":       t("verify.summary.new"),
            "missing":   t("verify.summary.missing"),
            "errors":    t("verify.summary.errors"),
        }

        for path in result.unchanged:
            self.tree.insert("", "end",
                             values=(status_labels["unchanged"], path),
                             tags=("unchanged",))
        for entry in result.modified:
            self.tree.insert("", "end",
                             values=(status_labels["modified"], entry.path),
                             tags=("modified",))
        for path in result.new:
            self.tree.insert("", "end",
                             values=(status_labels["new"], path),
                             tags=("new",))
        for path in result.missing:
            self.tree.insert("", "end",
                             values=(status_labels["missing"], path),
                             tags=("missing",))
        for entry in result.errors:
            self.tree.insert(
                "", "end",
                values=(status_labels["errors"], f"{entry.path}  ->  {entry.error}"),
                tags=("errors",),
            )


# ======================================================================
# Tab 3 — Report convert
# ======================================================================
class ReportTab(_BaseTab):
    def _build(self) -> None:
        self.columnconfigure(1, weight=1)

        self.input_var = tk.StringVar()
        self._path_row(0, t("report.input"), self.input_var, self._pick_input)

        ttk.Label(self, text=t("report.format")).grid(row=1, column=0, sticky="w", pady=4)
        self.format_var = tk.StringVar(value="csv")
        ttk.Combobox(
            self,
            textvariable=self.format_var,
            values=["csv", "json"],
            state="readonly",
            width=20,
        ).grid(row=1, column=1, sticky="w", padx=(6, 0), pady=4)

        self.output_var = tk.StringVar()
        self._path_row(2, t("report.output"), self.output_var, self._pick_output)

        ttk.Button(
            self, text=t("report.btn"), command=self._on_run, style="Accent.TButton"
        ).grid(row=3, column=0, columnspan=3, sticky="e", pady=(12, 8))

        ttk.Label(self, text=t("report.log")).grid(row=4, column=0, sticky="w")
        self.output_area = ScrolledText(self, height=16, wrap="word", font=("Consolas", 10))
        self.output_area.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        self.rowconfigure(5, weight=1)

    def _pick_input(self) -> None:
        path = filedialog.askopenfilename(
            title=t("report.picker.input_title"),
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.input_var.set(path)

    def _pick_output(self) -> None:
        fmt = self.format_var.get()
        path = filedialog.asksaveasfilename(
            title=t("report.picker.output_title"),
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}"), ("All files", "*.*")],
            initialfile=f"report.{fmt}",
        )
        if path:
            self.output_var.set(path)

    def _on_run(self) -> None:
        inp = self.input_var.get().strip()
        if not inp:
            messagebox.showwarning(t("report.missing_title"), t("report.missing_body"))
            return
        fmt = self.format_var.get()
        explicit_out = self.output_var.get().strip() or None

        def work(emit: Callable[[_Message], None]) -> Path:
            if explicit_out:
                out = explicit_out
            else:
                in_path = Path(inp)
                out = (
                    str(in_path.with_suffix(".csv"))
                    if fmt == "csv"
                    else str(in_path.with_name(in_path.stem + ".converted.json"))
                )
            return convert_report(inp, out, fmt)

        self._append(t("report.log.start", inp=inp, fmt=fmt.upper()))
        self.app.run_async(
            work,
            status=t("report.running"),
            on_done=lambda path: self._append(t("report.log.done", path=path)),
            on_error=lambda exc: messagebox.showerror(t("report.err_title"), str(exc)),
        )

    def _append(self, text: str) -> None:
        self.output_area.insert("end", text)
        self.output_area.see("end")


# ======================================================================
# Module entry point
# ======================================================================
def run() -> int:
    app = HashToolApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(run())
