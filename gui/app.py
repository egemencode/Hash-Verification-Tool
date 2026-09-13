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
    hash_file_with_snapshot,
)
from core.history_manager import HistoryManager
from core.key_files import (
    KeyFileError,
    load_private_key,
    load_public_key,
    public_path_for,
)
from core.local_verify import LocalVerifyStore
from core.manifest_manager import (
    Manifest,
    ManifestIntegrityError,
    build_manifest_for_folder,
    manifest_from_hashed_file,
)
from core.scan_policy import (
    confirmations,
    evaluate_hash_request,
    first_blocking,
    warnings as policy_warnings,
)
from core.reporter import convert_report, report_to_csv, report_to_json
from core.verifier import Verifier
from core.vt_client import VirusTotalClient
from gui import theme
from gui.trust_presenter import collect_startup_warnings, describe_result
from gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    get_language,
    set_language,
    t,
)
from gui.views.history_view import HistoryView
from gui.views.settings_view import SettingsView
from gui.views.trust_check_view import TrustCheckView
from utils.logger import get_logger
from utils.settings import (
    KEY_VT_AUTOQUERY,
    AppSettings,
    SettingsError,
    clear_migration_warnings,
    history_path,
    load_settings,
    pending_migration_warnings,
    save_settings,
    trust_store_path,
)

log = get_logger("gui")

POLL_INTERVAL_MS = 100

# Tag → foreground colour for the verification result tree.
# Which rows get a colour. The colours themselves are looked up when the
# tags are configured, not here: this module is imported before the
# application has asked Windows which theme it is wearing, so a table
# built now would hold the light palette whatever the window ends up.
STATUS_TAGS = theme.RESULT_STATUSES

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

    The *target* receives an ``emit`` callback so it can push progress updates
    back to the UI thread (e.g. ``emit(_Message("progress", event))``) and a
    ``cancel`` predicate it is expected to consult. The worker itself enqueues
    the terminal ``"done"`` / ``"error"`` messages once *target* returns or
    raises.

    Cancellation is cooperative and the token is the worker's own, not the
    caller's: whoever holds the worker can stop it without having to reach
    back into the closure that is running.
    """

    def __init__(
        self,
        target: Callable[[Callable[["_Message"], None], Callable[[], bool]], Any],
    ) -> None:
        self._queue: "queue.Queue[_Message]" = queue.Queue()
        self._target = target
        self._cancel = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def join(self, timeout: float) -> None:
        """Bounded by construction: the target polls the token per file."""
        self._thread.join(timeout)

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
            result = self._target(self._emit, self._cancel.is_set)
            # A cancelled run has not produced a result the caller asked for,
            # and reporting "done" would let the UI render it as one.
            if self._cancel.is_set():
                self._queue.put(_Message("cancelled", None))
            else:
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

        # Handles of every after() script we scheduled, so teardown can cancel
        # them instead of letting Tk run them against destroyed widgets.
        self._after_ids: set[str] = set()

        # Load language preference *before* building any widgets.
        self._settings = load_settings()
        set_language(self._settings.get("language", DEFAULT_LANGUAGE))

        # Typed settings + persistent stores (history, fingerprints).
        self._app_settings = AppSettings.load()
        # If a legacy plaintext API key could not be scrubbed we must say so —
        # claiming "your key is now protected" would be false.
        self._migration_warnings = pending_migration_warnings()
        clear_migration_warnings()
        self._history_manager = HistoryManager(
            history_path(), limit=self._app_settings.history_limit
        )
        self._local_store = LocalVerifyStore(trust_store_path())
        # Touch both stores so a corrupt/unreadable file is detected (and
        # quarantined) now, while we still have a chance to tell the user.
        self._history_manager.all()
        self._local_store.all()
        self._startup_warning = collect_startup_warnings(
            settings_warnings=self._migration_warnings,
            history_warning=self._history_manager.load_warning,
            local_store_warning=self._local_store.load_warning,
        )

        # Sized for the collapsed screen, from the height its layout actually
        # asks for; showing the İleri area grows the window
        # (TrustCheckView._set_window_height) rather than leaving a large
        # empty region under the simple view.
        self.geometry(f"1020x{TrustCheckView.COLLAPSED_HEIGHT}")
        self.minsize(880, TrustCheckView.COLLAPSED_HEIGHT)
        self._apply_style()

        self._menubar: Optional[tk.Menu] = None
        self.notebook: Optional[ttk.Notebook] = None
        self._statusbar: Optional[ttk.Frame] = None
        self.status_var = tk.StringVar(value=t("status.ready"))
        self._worker: Optional[_Worker] = None

        # Secondary tool windows (History / Settings / Advanced), created
        # hidden and shown from the menu. The main window holds only the
        # single-page Trust Check screen, so a first-time user sees one screen.
        self._tool_windows: list[tk.Toplevel] = []
        self._history_win: Optional[tk.Toplevel] = None
        self._settings_win: Optional[tk.Toplevel] = None
        self._advanced_win: Optional[tk.Toplevel] = None

        # Trust-check related widgets that the menu / history rescan
        # callbacks need to talk to.
        self.trust_view: Optional[TrustCheckView] = None
        self.history_view: Optional[HistoryView] = None

        # Explicit close flow: the X button must go through destroy() so
        # in-flight scans are cancelled before the widgets disappear.
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self._render_ui()

        if self._startup_warning is not None:
            # Deferred so the dialog appears over a drawn window.
            self.schedule(300, self._show_startup_warning)

    def _show_startup_warning(self) -> None:
        warning = self._startup_warning
        if warning is None:
            return
        # Cleared first so the notice is shown exactly once per launch.
        self._startup_warning = None
        self._migration_warnings = []
        messagebox.showwarning(warning.title, warning.body)

    # ------------------------------------------------------------------
    # Chrome
    # ------------------------------------------------------------------
    def _apply_style(self) -> None:
        # Colour tokens (text, risk and badge colours) still come from our own
        # theme; the widget chrome — buttons, entries, tabs — comes from Sun
        # Valley for a modern Windows 11 look. set_theme() replaces clam's
        # widget styling but leaves our colour tokens (module attributes) intact.
        theme.apply(self)
        try:
            import sv_ttk

            sv_ttk.set_theme("dark" if theme.current_mode() == "dark" else "light")
            # Match the plain-Tk window background (padding, canvas parents) to
            # Sun Valley's surface so no clam-grey shows through at the edges.
            bg = ttk.Style(self).lookup("TFrame", "background")
            if bg:
                self.configure(background=bg)
        except Exception:
            pass  # fall back to our own clam-based chrome

    def _render_ui(self) -> None:
        """Build window title, menu, main screen and status bar from scratch."""
        self.title(f"{t('app.title')}  —  v{__version__}")
        self._build_menu()
        self._build_main()
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

        toolsmenu = tk.Menu(menubar, tearoff=False)
        toolsmenu.add_command(
            label=t("tab.history").strip(),
            command=lambda: self._open_tool_window(self._history_win),
        )
        toolsmenu.add_command(
            label=t("tab.settings_tab").strip(),
            command=lambda: self._open_tool_window(self._settings_win),
        )
        toolsmenu.add_separator()
        toolsmenu.add_command(
            label=t("tab.advanced").strip(),
            command=lambda: self._open_tool_window(self._advanced_win),
        )
        menubar.add_cascade(label=t("menu.tools"), menu=toolsmenu)

        helpmenu = tk.Menu(menubar, tearoff=False)
        helpmenu.add_command(label=t("menu.about"), command=self._show_about)
        menubar.add_cascade(label=t("menu.help"), menu=helpmenu)

        # Studio link on the menu bar — visible on the main screen, opens the
        # site in a browser. On the status bar it turned out to reliably trip a
        # Tk teardown crash in the test suite; the menu bar does not.
        menubar.add_command(
            label=t("footer.studio"),
            command=lambda: self._open_url("https://torpilstudio.com"),
        )

        for menu in (menubar, filemenu, settingsmenu, langmenu, toolsmenu, helpmenu):
            theme.style_menu(menu)
        self.config(menu=menubar)
        self._menubar = menubar

    def _build_main(self) -> None:
        """Single-page layout: the Trust Check screen fills the window.

        History, Settings and the power-user tools each live in their own
        window, created hidden and shown from the Tools menu. They are built
        up front (not lazily) so the views inside them exist for callbacks and
        for tests that hold a reference like ``app.hash_tab``.
        """
        self.notebook = None
        self._tool_windows = []

        self.trust_view = TrustCheckView(
            self,
            get_vt_client=self._make_vt_client,
            local_store=self._local_store,
            history_manager=self._history_manager,
            set_status=self.status_var.set,
            on_scan_recorded=self._refresh_history,
            get_online_enabled=lambda: self._app_settings.virustotal_autoquery,
        )
        self.trust_view.pack(fill="both", expand=True, padx=10, pady=(10, 0))

        # --- History (hidden window) ---------------------------------
        self._history_win = self._make_tool_window(t("tab.history").strip())
        self.history_view = HistoryView(
            self._history_win,
            self._history_manager,
            on_rescan_request=self._rescan_from_history,
        )
        self.history_view.pack(fill="both", expand=True, padx=8, pady=8)

        # --- Settings (hidden window) --------------------------------
        self._settings_win = self._make_tool_window(t("tab.settings_tab").strip())
        self.settings_view = SettingsView(
            self._settings_win,
            self._app_settings,
            on_settings_changed=self._on_settings_changed,
        )
        self.settings_view.pack(fill="both", expand=True, padx=8, pady=8)

        # --- Advanced power-user tools (hidden window) ---------------
        self._advanced_win = self._make_tool_window(t("tab.advanced").strip())
        advanced_nb = ttk.Notebook(self._advanced_win)
        advanced_nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.hash_tab = HashTab(advanced_nb, self)
        self.verify_tab = VerifyTab(advanced_nb, self)
        self.report_tab = ReportTab(advanced_nb, self)
        advanced_nb.add(self.hash_tab,   text=t("tab.hash"))
        advanced_nb.add(self.verify_tab, text=t("tab.verify"))
        advanced_nb.add(self.report_tab, text=t("tab.report"))

    def _make_tool_window(self, title: str) -> tk.Toplevel:
        """A secondary window that hides (not destroys) on close, so it and
        the view inside it survive to be reopened."""
        win = tk.Toplevel(self)
        win.title(f"{title} — {t('app.title')}")
        win.geometry("900x640")
        win.withdraw()
        win.transient(self)
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        # Do NOT call theme.apply() here: it switches the global ttk theme back
        # to clam and would undo Sun Valley for the whole app. ttk styling is
        # global, so this window already has it — just match its plain-Tk bg.
        try:
            bg = ttk.Style(self).lookup("TFrame", "background")
            if bg:
                win.configure(background=bg)
        except Exception:
            pass
        self._tool_windows.append(win)
        return win

    def _open_tool_window(self, win: Optional[tk.Toplevel]) -> None:
        if win is None:
            return
        win.deiconify()
        win.lift()
        win.focus_set()

    # ------------------------------------------------------------------
    # Trust-check plumbing
    # ------------------------------------------------------------------
    def _make_vt_client(self) -> VirusTotalClient:
        """Build a VirusTotal client using the latest saved API key."""
        return VirusTotalClient(
            api_key=self._app_settings.virustotal_api_key,
            timeout=15.0,
        )

    def _refresh_history(self) -> None:
        if self.history_view is not None:
            self.history_view.refresh()

    def _rescan_from_history(self, path: str) -> None:
        if self.trust_view is None:
            return
        # History lives in its own window; get it out of the way and bring the
        # main screen forward so the scan the user asked for is what they see.
        if self._history_win is not None:
            try:
                self._history_win.withdraw()
            except tk.TclError:
                pass
        try:
            self.lift()
            self.focus_set()
        except tk.TclError:
            pass
        # One API that either starts a scan of *this* path or reports why it
        # could not. Previously this set the path and then called _on_scan()
        # unconditionally, so a history entry whose file had been deleted
        # re-scanned whatever was selected before.
        if not self.trust_view.rescan_path(path):  # noqa: SLF001 — same package
            messagebox.showwarning(
                "Dosya bulunamadı",
                f"Bu geçmiş kaydındaki dosya artık yok:\n{path}\n\n"
                "Tarama başlatılmadı.",
            )

    def _on_settings_changed(self, new_settings: AppSettings) -> None:
        self._app_settings = new_settings
        # Persist the legacy raw-dict language slot too so the menu
        # bar's prefix-aware rebuild keeps working.
        # AppSettings.save() (in the settings view) has already persisted
        # everything. Writing our startup snapshot back here is what used to
        # revert the user's privacy choice — keep the in-memory copy in sync
        # instead, and do not touch the disk again.
        self._settings["language"] = new_settings.language
        self._settings[KEY_VT_AUTOQUERY] = new_settings.virustotal_autoquery
        # Refresh the history limit on the live manager.
        self._history_manager = HistoryManager(
            history_path(), limit=new_settings.history_limit
        )
        if self.history_view is not None:
            self.history_view._history = self._history_manager  # noqa: SLF001
            self.history_view.refresh()
        if self.trust_view is not None:
            self.trust_view._history = self._history_manager  # noqa: SLF001
            # Reflect a changed privacy preference on the main screen at once.
            self.trust_view._refresh_online_state()  # noqa: SLF001

        # If the language was changed via the Settings tab, rebuild the
        # chrome live — otherwise the new locale would only kick in on
        # the next launch and the "Kaydet hemen uygulanır" copy would
        # be a lie.
        if new_settings.language != get_language():
            self._switch_language(new_settings.language)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel", anchor="w").pack(
            side="left", fill="x", expand=True
        )
        # Determinate by default so we can display an actual percentage
        # as soon as the worker starts emitting ProgressEvents.
        self.progress = ttk.Progressbar(bar, mode="determinate", length=200, maximum=100)
        # In the status bar rather than on a tab: one worker slot serves Hash,
        # Verify and Report, so one control stops whichever is running.
        self.cancel_button = ttk.Button(
            bar, text=t("btn.cancel"), command=self._on_cancel
        )
        self.cancel_button.state(["disabled"])
        # Deliberately not packed here. These belong to the Advanced tools'
        # worker; on the single-page screen an empty progress bar and a dead
        # Cancel button are just clutter. _show_worker_controls() puts them on
        # screen for exactly as long as a job runs.
        self._statusbar = bar

    def _show_worker_controls(self) -> None:
        """Reveal the worker's progress bar and Cancel button."""
        self.progress.pack(side="right", padx=8, pady=4)
        self.cancel_button.pack(side="right", padx=(0, 4), pady=4)

    def _hide_worker_controls(self) -> None:
        self.progress.pack_forget()
        self.cancel_button.pack_forget()

    # ------------------------------------------------------------------
    # Language switching — tear down chrome, rebuild in the new locale.
    # ------------------------------------------------------------------
    def schedule(self, delay_ms: int, callback, *args):
        """
        Register an ``after()`` callback so it can be cancelled on teardown.

        Every scheduled script must go through here. Tk keeps running a
        pending after() script once its widget is destroyed and then reports
        `invalid command name ...` on stderr — harmless-looking noise that
        hides real errors and, in a frozen build, surfaces as a crash dialog.
        """
        handle: list[str] = []

        def _run(*inner):
            self._after_ids.discard(handle[0] if handle else "")
            return callback(*inner)

        after_id = self.after(delay_ms, _run, *args)
        handle.append(after_id)
        self._after_ids.add(after_id)
        return after_id

    def _cancel_scheduled_callbacks(self) -> None:
        for after_id in list(self._after_ids):
            try:
                self.after_cancel(after_id)
            except tk.TclError:  # pragma: no cover - already gone
                pass
        self._after_ids.clear()

    def _shutdown_active_scans(self) -> None:
        """Cancel in-flight trust scans so late callbacks hit no live widgets."""
        if self.trust_view is not None:
            try:
                self.trust_view.shutdown()
            except Exception:
                log.exception("trust view shutdown failed")

    def _shutdown_background_worker(self) -> None:
        """
        Stop the Hash / Verify / Report worker and wait for it to notice.

        Not merely tidiness. That worker is what writes the manifest — it calls
        ``build.save()`` itself — so a window closed mid-scan used to leave a
        reference file on disk for a scan the user had walked away from. The
        join is bounded because the token is polled once per file.
        """
        worker = self._worker
        if worker is None:
            return
        worker.cancel()
        if worker.is_alive():
            worker.join(timeout=5.0)
        self._worker = None

    def destroy(self) -> None:  # type: ignore[override]
        # Tk tears the widgets down here; a worker delivering afterwards would
        # otherwise raise from a dead callback.
        self._shutdown_active_scans()
        self._shutdown_background_worker()
        self._cancel_scheduled_callbacks()
        super().destroy()

    def _switch_language(self, lang: str) -> None:
        if lang == get_language():
            return
        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo(t("status.busy_title"), t("status.busy_body"))
            return
        if self.trust_view is not None and self.trust_view.is_busy:
            # Rebuilding the chrome destroys the widgets a running scan will
            # call back into; make the user wait rather than crash later.
            messagebox.showinfo(t("status.busy_title"), t("status.busy_body"))
            return
        # The notebook (and the trust view inside it) is about to be rebuilt.
        self._shutdown_active_scans()

        set_language(lang)
        self._settings["language"] = lang
        # Third holder of the same value, and the one the Settings tab is
        # rebuilt from. Leaving it stale is what let the next save in that tab
        # write the previous language back and switch the UI to it — silently
        # undoing a choice the user had already made and seen take effect.
        self._app_settings.language = lang
        try:
            save_settings(self._settings)
        except SettingsError as exc:
            messagebox.showwarning(
                t("settings.language.save_failed_title"),
                t("settings.language.save_failed_body", error=exc),
            )

        if self._menubar is not None:
            self._menubar.destroy()
            self._menubar = None
        # Tear down the main screen and every tool window; _render_ui rebuilds
        # them in the new locale. Dropping the refs keeps a late callback from
        # touching a freed widget.
        for win in list(self._tool_windows):
            try:
                win.destroy()
            except tk.TclError:
                pass
        self._tool_windows = []
        self._history_win = None
        self._settings_win = None
        self._advanced_win = None
        if self.trust_view is not None:
            try:
                self.trust_view.destroy()
            except tk.TclError:
                pass
            self.trust_view = None
        self.history_view = None
        self.settings_view = None
        if self._statusbar is not None:
            self._statusbar.destroy()
            self._statusbar = None

        self._render_ui()

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
        self._show_worker_controls()
        self._worker = _Worker(target)
        self.cancel_button.state(["!disabled"])
        self._worker.start()
        self.schedule(POLL_INTERVAL_MS, self._poll, on_done, on_error, on_progress)

    def _on_cancel(self) -> None:
        """
        Stop whichever operation is running.

        Cooperative: the token is polled once per file, so a large file still
        has to finish. The button disables itself and the status line says what
        is happening rather than claiming the work already stopped — and the
        terminal state is announced by _poll when the worker actually returns.
        """
        worker = self._worker
        if worker is None or not worker.is_alive():
            return
        worker.cancel()
        self.cancel_button.state(["disabled"])
        self.status_var.set(t("status.cancelling"))

    def _poll(
        self,
        on_done: Callable[[Any], None],
        on_error: Optional[Callable[[Exception], None]],
        on_progress: Optional[Callable[[ProgressEvent], None]],
    ) -> None:
        worker = self._worker
        if worker is None:
            return
        if self._dispatch(worker.drain(), on_done, on_error, on_progress):
            return
        if worker.is_alive():
            self.schedule(POLL_INTERVAL_MS, self._poll, on_done, on_error, on_progress)
            return
        # The thread queues its terminal message and *then* returns, so a
        # drain that came up empty a moment ago says nothing about whether one
        # has arrived since. Looking once more here is the difference between
        # reporting the run and discarding it: _finish drops the reference to
        # the worker, so a message missed at this point is missed for good —
        # a hash run that wrote its manifest, or a verify that failed, and
        # then said "Hazır." and showed nothing.
        if self._dispatch(worker.drain(), on_done, on_error, on_progress):
            return
        self._finish(t("status.ready"))

    def _dispatch(
        self,
        messages: list["_Message"],
        on_done: Callable[[Any], None],
        on_error: Optional[Callable[[Exception], None]],
        on_progress: Optional[Callable[[ProgressEvent], None]],
    ) -> bool:
        """Render *messages*; True once a terminal one has been handled."""
        for msg in messages:
            if msg.kind == "progress":
                event: ProgressEvent = msg.payload
                self.progress["value"] = event.percent
                if on_progress is not None:
                    on_progress(event)
                continue
            if msg.kind == "cancelled":
                # No on_done: the operation produced nothing the user asked
                # for, and the tabs' _on_done render a completed result.
                self._finish(t("status.cancelled"))
                return True
            if msg.kind == "done":
                self.progress["value"] = 100
                self._finish(t("status.ready"))
                on_done(msg.payload)
                return True
            if msg.kind == "error":
                self._finish(t("status.error"))
                if on_error:
                    on_error(msg.payload)
                else:
                    messagebox.showerror(t("status.error"), str(msg.payload))
                return True
        return False

    def _finish(self, status: str) -> None:
        self.progress["value"] = 0
        self.status_var.set(status)
        self._worker = None
        self.cancel_button.state(["disabled"])
        self._hide_worker_controls()

    # ------------------------------------------------------------------
    def _open_url(self, url: str) -> None:
        import webbrowser
        try:
            webbrowser.open_new_tab(url)
        except Exception:
            log.exception("could not open %s", url)

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

        # An unsigned manifest proves nothing on its own: whoever can change
        # the files can change the reference too. The placement rules that make
        # a signature mean something come from the same table the CLI uses.
        self.sign_key_var = tk.StringVar()
        self._path_row(4, t("hash.sign_key"), self.sign_key_var, self._pick_sign_key)
        ttk.Label(
            self, text=t("hash.sign_key.hint"), foreground=theme.MUTED, wraplength=680,
            justify="left",
        ).grid(row=5, column=1, columnspan=2, sticky="w", pady=(0, 6))

        ttk.Button(
            self, text=t("hash.btn"), command=self._on_run, style="Accent.TButton"
        ).grid(row=6, column=0, columnspan=3, sticky="e", pady=(12, 8))

        ttk.Label(self, text=t("hash.result")).grid(row=7, column=0, sticky="w")
        self.output_area = ScrolledText(self, height=18, wrap="word", font=theme.FONT_MONO)
        theme.style_text_area(self.output_area)
        self.output_area.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        self.rowconfigure(8, weight=1)

    def _pick_target(self) -> None:
        if self.mode_var.get() == "file":
            path = filedialog.askopenfilename(title=t("hash.picker.file_title"))
        else:
            path = filedialog.askdirectory(title=t("hash.picker.folder_title"))
        if path:
            self.target_var.set(path)

    def _pick_sign_key(self) -> None:
        path = filedialog.askopenfilename(title=t("hash.picker.sign_key_title"))
        if path:
            self.sign_key_var.set(path)

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
        # This runs on the Tk main thread, where an uncaught exception is
        # printed to stderr and nothing else happens — the button appears dead.
        # A drive root or a bare UNC share has no filename to put a default
        # manifest beside, so this is a real input, not a defensive flourish.
        try:
            saved_to = output or (
                None if mode == "file"
                else str(Path(target).with_name("manifest.json"))
            )
        except (ValueError, OSError) as exc:
            messagebox.showerror(
                t("hash.err_title"),
                t("hash.no_default_output", target=target, error=exc),
            )
            return

        sign_key_path = self.sign_key_var.get().strip() or None
        if sign_key_path and mode == "file":
            # Matching the CLI: a signature attests to a folder inventory, and
            # a single-file digest is not one.
            messagebox.showerror(t("hash.err_title"), t("hash.sign_key.folder_only"))
            return

        # The same decision table the CLI uses, so the graphical path cannot
        # end up being the permissive one. Evaluated before any hashing: a
        # refusal must leave nothing behind.
        notices = evaluate_hash_request(
            mode=mode, target=target, output=saved_to, algorithm=algo,
            sign_key=sign_key_path,
        )
        blocking = first_blocking(notices)
        if blocking is not None:
            messagebox.showerror(t("hash.blocked_title"), blocking.message)
            self._append(f"\n⛔ {blocking.message}\n")
            return
        for notice in confirmations(notices):
            if not messagebox.askyesno(
                t("hash.confirm_title"),
                notice.message + "\n\n" + t("hash.confirm_question"),
                icon="warning",
                default="no",
            ):
                self._append(f"\n⏹ {t('hash.log.cancelled')}\n")
                return
            self._append(f"\n⚠ {notice.message}\n")
        for notice in policy_warnings(notices):
            self._append(f"\n⚠ {notice.message}\n")

        # Resolved before any hashing starts, so a key that cannot be read
        # costs nothing and is reported as the input error it is. Discovering
        # it after the scan would mean either throwing the work away or — far
        # worse — writing the manifest unsigned while the user believes they
        # signed it.
        signing_key = None
        if sign_key_path:
            try:
                # The hex, not the loaded file object: Manifest.sign takes the
                # key material.
                signing_key = load_private_key(sign_key_path).private_hex
            except KeyFileError as exc:
                messagebox.showerror(t("hash.err_title"), str(exc))
                self._append(f"\n⛔ {exc}\n")
                return

        self._append(t("hash.log.header", mode=mode, algo=algo, target=target))

        def work(
            emit: Callable[[_Message], None], cancel: Callable[[], bool]
        ) -> dict[str, Any]:
            if mode == "file":
                # One read: the digest shown and the digest stored describe
                # the same bytes. Strict only when it becomes a stored
                # reference; printing a checksum of a live file stays lenient.
                digest, snapshot = hash_file_with_snapshot(
                    target, algorithm=algo, ensure_stable=bool(output)
                )
                saved = None
                if output:
                    manifest_from_hashed_file(
                        target, algo, digest, snapshot
                    ).save(output)
                    saved = output
                emit(_Message("progress", ProgressEvent(done=1, total=1, path=target)))
                return {"mode": "file", "digest": digest, "output": saved}

            def on_progress(event: ProgressEvent) -> None:
                emit(_Message("progress", event))

            build = build_manifest_for_folder(
                target, algorithm=algo, on_progress=on_progress,
                exclude=[saved_to], cancel=cancel,
            )
            manifest = build.manifest
            # Signed before it is written, and only when the scan is complete:
            # a signature over a description that knowingly has holes in it
            # would attest to exactly the gaps it fails to mention.
            if signing_key is not None and build.complete:
                manifest.sign(signing_key)
            # Only a complete build produces a manifest at the expected path;
            # BuildResult.save() refuses otherwise, so we never write first
            # and warn afterwards.
            written = build.save(saved_to) if build.complete else None
            return {
                "mode": "folder",
                "build": build,
                "count": len(manifest.entries),
                "output": str(written) if written else None,
                "signed": signing_key is not None and build.complete,
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
            if result["output"]:
                self._append(t("hash.log.saved", path=result["output"]))
            if result.get("signed"):
                # Name the public half: a signature nobody can check against a
                # key they trust is decoration.
                self._append(t(
                    "hash.log.signed",
                    pub=public_path_for(self.sign_key_var.get().strip()),
                ))
            build = result.get("build")
            if build is not None and not build.complete:
                # Never announce a clean "manifest created" for a folder we
                # could not read in full — the gaps are exactly where an
                # unnoticed change would hide.
                detail = (
                    f"{len(build.skipped)} dosya atlandı, "
                    f"{len(build.changed_during_scan)} dosya tarama sırasında değişti."
                )
                self._append(f"\n⚠ TARAMA TAMAMLANAMADI — {detail}\n")
                self._append("    Manifest YAZILMADI.\n")
                for rel, reason in build.errors[:10]:
                    self._append(f"    atlandı: {rel} -> {reason}\n")
                messagebox.showwarning(
                    "Manifest oluşturulmadı",
                    "Klasörün tamamı taranamadığı için manifest "
                    "kaydedilmedi.\n\n" + detail
                    + "\n\nEksik bir manifest, taranamayan dosyaları sonsuza "
                    "kadar 'değişmemiş' gösterirdi.",
                )
                return
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

        # Next to the manifest, because it is a fact *about* the manifest.
        # Without it the best reachable verdict is "signed, but the source is
        # not verified" — which is what the CLI needs --trusted-key for.
        self.trusted_key_var = tk.StringVar()
        self._path_row(
            2, t("verify.trusted_key"), self.trusted_key_var, self._pick_trusted_key
        )
        ttk.Label(
            self, text=t("verify.trusted_key.hint"), foreground=theme.MUTED, wraplength=680,
            justify="left",
        ).grid(row=3, column=1, columnspan=2, sticky="w", pady=(0, 6))

        self.report_var = tk.StringVar()
        self._path_row(4, t("verify.report"), self.report_var, self._pick_report)

        ttk.Button(
            self, text=t("verify.btn"), command=self._on_run, style="Accent.TButton"
        ).grid(row=5, column=0, columnspan=3, sticky="e", pady=(12, 8))

        ttk.Label(self, text=t("verify.summary")).grid(row=6, column=0, sticky="w")
        self.summary = ScrolledText(self, height=7, wrap="word", font=theme.FONT_MONO)
        theme.style_text_area(self.summary)
        self.summary.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(4, 6))

        ttk.Label(self, text=t("verify.details")).grid(row=8, column=0, sticky="w")
        self.tree = ttk.Treeview(
            self, columns=("status", "path"), show="headings", height=14
        )
        self.tree.heading("status", text=t("verify.col.status"))
        self.tree.heading("path", text=t("verify.col.path"))
        self.tree.column("status", width=130, anchor="w", stretch=False)
        self.tree.column("path", anchor="w")
        self.tree.grid(row=9, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        for tag in STATUS_TAGS:
            color = theme.result_colour(tag)
            self.tree.tag_configure(tag, foreground=color)
        self.rowconfigure(9, weight=1)

    def _pick_folder(self) -> None:
        path = filedialog.askdirectory(title=t("verify.picker.folder_title"))
        if path:
            self.folder_var.set(path)

    def _pick_trusted_key(self) -> None:
        path = filedialog.askopenfilename(
            title=t("verify.picker.trusted_key_title"),
            filetypes=[("Public key", "*.pub"), ("All files", "*.*")],
        )
        if path:
            self.trusted_key_var.set(path)

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

        # Resolved here, on the Tk thread, so an unusable key is reported as
        # the input error it is. Falling through to an untrusted comparison
        # would render a screen indistinguishable from a successful one — the
        # user would believe they had checked provenance when they had not.
        raw_key = self.trusted_key_var.get().strip()
        trusted_key = None
        if raw_key:
            try:
                trusted_key = load_public_key(raw_key)
            except KeyFileError as exc:
                messagebox.showerror(t("verify.err_title"), str(exc))
                return

        self.summary.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.summary.insert("end", t("verify.running") + "\n")

        report_path = self.report_var.get().strip() or None

        def work(
            emit: Callable[[_Message], None], cancel: Callable[[], bool]
        ) -> dict:
            manifest = Manifest.load(manifest_path, trusted_public_hex=trusted_key)

            def on_progress(event: ProgressEvent) -> None:
                emit(_Message("progress", event))

            result = Verifier(manifest, trusted_public_hex=trusted_key).verify(
                folder, on_progress=on_progress, cancel=cancel
            )
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

        def show_error(exc: Exception) -> None:
            if isinstance(exc, ManifestIntegrityError):
                # A tampered/unverifiable manifest is a security event, not a
                # generic failure — give it its own unmistakable dialog.
                messagebox.showerror(
                    "Manifest Bütünlük Hatası",
                    f"{exc}\n\n"
                    "Doğrulama YAPILMADI. Bu manifest dosyası değiştirilmiş "
                    "olabilir; sonuçlara güvenmeyin.",
                )
                self.summary.delete("1.0", "end")
                self.summary.insert(
                    "end",
                    "✖ Manifest imzası doğrulanamadı — doğrulama durduruldu.\n",
                )
                return
            messagebox.showerror(t("verify.err_title"), str(exc))

        self.app.run_async(
            work,
            status=t("verify.running"),
            on_done=self._on_done,
            on_error=show_error,
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

        # Manifest provenance is shown as its own line: "files match" and
        # "the manifest can be trusted" are separate facts, and a match
        # against an unverified manifest must not read as an unqualified
        # "clean" result.
        headline, badge = describe_result(result)
        self.summary.insert("end", f"\n{headline.icon} {headline.text}\n")
        self.summary.insert("end", f"\n{badge.icon} Manifest güveni: {badge.label}\n")
        self.summary.insert("end", f"   {badge.detail}\n")
        if not badge.provenance_established:
            self.summary.insert("end", f"   {t('verify.trusted_key.tip')}\n")
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
        self.output_area = ScrolledText(self, height=16, wrap="word", font=theme.FONT_MONO)
        theme.style_text_area(self.output_area)
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

        # Report conversion is a single file operation with no per-item loop to
        # break out of, so it accepts the token and does not consult it.
        def work(
            emit: Callable[[_Message], None], cancel: Callable[[], bool]
        ) -> Path:
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
