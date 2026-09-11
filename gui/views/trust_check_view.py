"""
Primary "Güven Kontrolü" screen — the friendly, one-button surface.

Layout (top to bottom):
  1. Drop / pick zone showing the currently selected file.
  2. Big risk badge + headline + bullet summary.
  3. Collapsible "Teknik Detay" panel: file info, hashes, VirusTotal raw
     stats, signature, local fingerprint.
  4. Action row: re-scan, save fingerprint, export report.
"""

from __future__ import annotations

import os
import threading
import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Optional

from core.baseline import (
    decision_prompt,
    BaselineDecision,
    evaluate_baseline_request,
)
from core.hash_utils import HashError, compute_file_hashes
from core.local_verify import LocalStoreError, LocalVerifyStatus, LocalVerifyStore
from core.scan_controller import ScanCancelled, ScanController, ControllerState
from core.risk_engine import RiskLevel
from gui import theme
from gui.i18n import get_language, t
from gui.trust_presenter import render_summary
from core.signature_checker import SignatureStatus
from core.trust_pipeline import (
    TrustResult,
    resolve_online_checks,
    run_trust_check,
)
from core.trust_report import TrustReportError, export_html, export_json
from core.vt_client import VirusTotalClient, VTStatus
from core.history_manager import HistoryManager, HistoryStoreError, make_entry
from utils.logger import get_logger

log = get_logger("gui.trust")


# Passed to windnd.hook_dropfiles. `force_unicode` makes it call DragQueryFileW
# and hand back `str`; without it the library uses the ANSI DragQueryFile, whose
# bytes are in the active code page and cannot represent every filename NTFS
# accepts (an emoji arrives as "?"). Kept as a module constant so the wiring is
# testable — a silently ANSI drop path is invisible until someone drops a file
# with the wrong name.
DROP_HOOK_KWARGS: dict[str, object] = {"force_unicode": True}


def decode_dropped_path(raw: bytes | str) -> str:
    """
    Turn a dropped path from the drag-and-drop library into a usable string.

    With :data:`DROP_HOOK_KWARGS` the library already hands back ``str`` and
    this is a pass-through. The bytes branch exists because the decoding is not
    knowable from the value alone — an older library build, or one that ignores
    the flag, delivers active-code-page bytes, while ``os.fsencode`` output is
    UTF-8 with surrogatepass. Guessing wrong is not cosmetic: the caller ends up
    with a path that does not exist and the user is told their file is missing.

    So each plausible decoding is tried and the first one that names a real file
    wins. A dropped path exists by construction, which is what makes that test
    meaningful. The code page goes first because some ANSI byte sequences are
    also well-formed UTF-8 (cp1254 ``Ã§`` is the pair the UTF-8 reader sees as
    ``ç``), so both readings can name files that exist side by side and only the
    order picks the one actually dropped. Nothing here may raise: this runs
    inside a ctypes callback where an exception unwinds into the window
    procedure, skipping ``DragFinish`` and leaving the drop to do nothing at all
    with no message.
    """
    if isinstance(raw, str):
        return raw

    candidates: list[str] = []
    for decoder in (lambda b: b.decode("mbcs"), os.fsdecode):
        try:
            decoded = decoder(raw)
        except (UnicodeDecodeError, UnicodeError, LookupError, ValueError):
            continue
        if decoded not in candidates:
            candidates.append(decoded)
        try:
            if os.path.exists(decoded):
                return decoded
        except (OSError, ValueError):
            continue

    if candidates:
        return candidates[0]
    # Last resort: never propagate out of the drop callback.
    return raw.decode("mbcs", errors="replace")


# Risk level → the i18n key for its badge text.
#
# Keys, and no colours at all. This table is built once at import, and both
# halves would be frozen there: the label in whichever language was active
# when Python first read the file, and the colour in whichever palette — both
# chosen later, when the window is built. So the table holds the one thing
# that does not change, and risk_presentation() looks up the rest.
RISK_BADGE_KEYS: dict[str, str] = {
    RiskLevel.LOW.value:     "risk.badge.low",
    RiskLevel.MEDIUM.value:  "risk.badge.medium",
    RiskLevel.HIGH.value:    "risk.badge.high",
    RiskLevel.UNKNOWN.value: "risk.badge.unknown",
}


def wrap_to_column(label: ttk.Label) -> None:
    """
    Wrap *label* at the width the layout gives it, not at a number picked once.

    A fixed ``wraplength`` is a guess about how wide the column will turn out,
    and the failure mode when the guess is too generous is not "wraps late" —
    it is "does not wrap at all". Tk lays the text out as one long line and the
    container simply cuts it at its edge, with no ellipsis to say so. The
    drop-zone sentence shipped that way: 86 pixels of it were missing in
    Turkish, 8 in English, and in both cases the word lost was the last one.

    Binding to ``<Configure>`` follows the column instead of predicting it, so
    it holds for a language whose sentence is longer and for a user who
    resizes the window.
    """
    def on_configure(event) -> None:
        # Guard both ways: a width of 1 is an unmapped widget, and re-setting
        # the same value would have this handler answer its own event forever.
        #
        # An unset wraplength reads back as "", not 0, and int("") raises.
        # That mattered more than it looks: the exception surfaced inside a Tk
        # callback, where it is printed and swallowed, so the handler simply
        # stopped doing its job and the label went on being cut off.
        current = str(label.cget("wraplength")).strip() or "0"
        if event.width > 1 and int(current) != event.width:
            label.configure(wraplength=event.width)

    label.bind("<Configure>", on_configure)


def risk_presentation(level: str) -> tuple[str, str]:
    """Badge colour and translated label for *level*, both looked up now."""
    key = RISK_BADGE_KEYS.get(level, RISK_BADGE_KEYS[RiskLevel.UNKNOWN.value])
    return theme.risk_colour(level), t(key)


# Signature states the panel spells out. Unlike the History column's five
# buckets this keeps every distinction the checker makes, because the panel
# has room for a sentence and the column does not.
_SIGNATURE_KEYS = {
    SignatureStatus.SIGNED_VALID:   "trust.sig.signed_valid",
    SignatureStatus.HASH_MISMATCH:  "trust.sig.hash_mismatch",
    SignatureStatus.UNTRUSTED:      "trust.sig.untrusted",
    SignatureStatus.UNSIGNED:       "trust.sig.unsigned",
    SignatureStatus.NOT_APPLICABLE: "trust.sig.not_applicable",
    SignatureStatus.UNKNOWN:        "trust.sig.unknown",
    SignatureStatus.UNSUPPORTED:    "trust.sig.unsupported",
    SignatureStatus.ERROR:          "trust.sig.error",
}

_LOCAL_KEYS = {
    LocalVerifyStatus.SAME:        "trust.local.same",
    LocalVerifyStatus.CHANGED:     "trust.local.changed",
    LocalVerifyStatus.NEW:         "trust.local.new",
    LocalVerifyStatus.NOT_TRACKED: "trust.local.not_tracked",
}


class TrustCheckView(ttk.Frame):
    """Single-file trust-check workflow."""

    def __init__(
        self,
        parent: ttk.Notebook,
        *,
        get_vt_client: Callable[[], VirusTotalClient],
        local_store: LocalVerifyStore,
        history_manager: HistoryManager,
        set_status: Callable[[str], None],
        on_scan_recorded: Optional[Callable[[], None]] = None,
        # Reads the *live* preference each scan, so toggling it in Settings
        # takes effect immediately without rebuilding the view.
        get_online_enabled: Callable[[], bool] = lambda: False,
    ) -> None:
        super().__init__(parent, padding=14)
        self._get_vt_client = get_vt_client
        self._get_online_enabled = get_online_enabled
        self._local_store = local_store
        self._history = history_manager
        self._push_status = set_status
        self._on_scan_recorded = on_scan_recorded

        # Single source of truth for "which file is this result about".
        self._controller = ScanController()
        self._selected_path: Optional[str] = None
        self._last_result: Optional[TrustResult] = None
        self._busy = False
        # Handle of the single scheduled poll callback (None when none is
        # pending). Tk keeps running an after() script after the widget is
        # destroyed unless it is explicitly cancelled.
        self._poll_after_id: Optional[str] = None
        self._status_text = ""
        self._msg_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()

        self._build()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        # The advanced area (row 3) grows; the simple screen above it stays
        # compact. For a first-time user the whole screen is: drop a file,
        # read the verdict, done. Everything technical — the SHA-256 string,
        # the save/export buttons, the per-check detail tabs — lives inside a
        # collapsed "İleri" area they never have to open.
        self.rowconfigure(3, weight=1)

        self._build_drop_zone(row=0)
        self._build_summary_panel(row=1)
        self._build_simple_actions(row=2)
        self._build_advanced_area(row=3)

    # --- Simple actions + advanced toggle -----------------------------
    def _build_simple_actions(self, row: int) -> None:
        frame = ttk.Frame(self)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=1)

        self.rescan_btn = ttk.Button(
            frame, text=t("trust.btn.rescan"), command=self._on_scan
        )
        self.rescan_btn.grid(row=0, column=0, sticky="w")
        self.rescan_btn.state(["disabled"])

        # One control reveals everything technical at once.
        self._details_toggle_var = tk.StringVar(value=t("trust.details.show"))
        self._details_toggle_btn = ttk.Button(
            frame,
            textvariable=self._details_toggle_var,
            command=self._toggle_details,
        )
        self._details_toggle_btn.grid(row=0, column=1, sticky="e")

    def _build_advanced_area(self, row: int) -> None:
        """Everything technical, collapsed by default under the İleri toggle."""
        container = ttk.Frame(self)
        # NOT gridded yet — collapsed. _toggle_details() reveals it.
        container.columnconfigure(0, weight=1)
        container.rowconfigure(2, weight=1)
        self._advanced_container = container
        self._details_visible = False

        self._build_fingerprint_panel(container, row=0)
        self._build_export_row(container, row=1)
        self._build_details_notebook(container, row=2)

    # --- Drop zone ----------------------------------------------------
    def _build_drop_zone(self, row: int) -> None:
        frame = ttk.LabelFrame(self, text=t("trust.section.pick"), padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.file_label_var = tk.StringVar(value=t("trust.no_file"))
        file_label = ttk.Label(
            frame,
            textvariable=self.file_label_var,
            justify="left",
        )
        file_label.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        wrap_to_column(file_label)

        btns = ttk.Frame(frame)
        btns.grid(row=0, column=1, sticky="e")
        ttk.Button(
            btns, text=t("trust.btn.pick"), command=self._pick_file,
            style="Accent.TButton",
        ).pack(side="left")
        self.scan_button = ttk.Button(
            btns, text=t("trust.btn.scan"), command=self._on_scan
        )
        self.scan_button.pack(side="left", padx=(8, 0))
        self.scan_button.state(["disabled"])
        # Enabled only while a scan runs — see _set_busy. Without it the only
        # way to stop a scan was to close the window, so picking the wrong
        # file meant waiting the whole scan out.
        self.cancel_button = ttk.Button(
            btns, text=t("btn.cancel"), command=self._on_cancel
        )
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.cancel_button.state(["disabled"])

        # Privacy state must be visible on the main screen, not buried in
        # Settings: the user should always know whether anything leaves the
        # machine before they start a scan.
        self.online_state_var = tk.StringVar()
        ttk.Label(
            btns, textvariable=self.online_state_var, foreground=theme.TEXT
        ).pack(side="left", padx=(16, 0))
        # NOTE: `frame` is laid out with grid; adding a packed child here
        # raises TclError and the whole app fails to open. One geometry
        # manager per container.
        ttk.Label(
            frame, text=t("privacy.notice"), foreground=theme.MUTED, wraplength=680,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._refresh_online_state()

        # Lightweight drag-and-drop via the windnd library if installed.
        # No hard dependency: if windnd isn't there we silently skip.
        try:
            import windnd  # type: ignore

            def _on_drop(paths: list[bytes]) -> None:
                # Runs inside a ctypes window procedure. An exception escaping
                # here skips the library's DragFinish and leaks the drop
                # handle, and the user sees nothing happen at all.
                try:
                    if not paths:
                        return
                    self._set_selected_path(decode_dropped_path(paths[0]))
                except Exception:  # noqa: BLE001 - must not unwind into ctypes
                    log.exception("drag-and-drop handling failed")

            windnd.hook_dropfiles(self, func=_on_drop, **DROP_HOOK_KWARGS)
        except Exception:
            pass

    def _refresh_online_state(self) -> None:
        """Show whether this scan will contact VirusTotal."""
        enabled = False
        try:
            enabled = resolve_online_checks(
                autoquery=self._get_online_enabled(),
                has_key=self._get_vt_client().has_key,
            )
        except Exception:  # never let a settings problem break the screen
            enabled = False
        self.online_state_var.set(
            t("trust.online.on") if enabled else t("trust.online.off")
        )

    # --- Summary ------------------------------------------------------
    def _build_summary_panel(self, row: int) -> None:
        frame = ttk.LabelFrame(self, text=t("trust.section.summary"), padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(1, weight=1)

        self.badge_canvas = tk.Canvas(
            frame, width=140, height=58, highlightthickness=0, bg=self._bg(frame)
        )
        self.badge_canvas.grid(row=0, column=0, sticky="w", padx=(0, 16), rowspan=3)
        self._draw_badge(theme.MUTED, "—")

        self.headline_var = tk.StringVar(value=t("trust.summary.idle"))
        ttk.Label(
            frame,
            textvariable=self.headline_var,
            font=theme.FONT_HEADING,
            wraplength=700,
            justify="left",
        ).grid(row=0, column=1, sticky="w")

        self.bullets_text = tk.Text(
            frame,
            height=4,
            wrap="word",
            bd=0,
            font=theme.FONT_UI,
        )
        # Took its ground from the theme and its text from Tk's default, which
        # is black. On light that was invisible luck; on dark it is black text
        # on a dark card. The summary is the point of this screen.
        theme.style_text_area(self.bullets_text)
        self.bullets_text.configure(background=self._bg(frame))
        self.bullets_text.grid(row=1, column=1, sticky="ew", pady=(8, 8))
        self.bullets_text.configure(state="disabled")
        # Narrowing the window re-wraps the sentences, so what fits changes
        # with it. Width only: reacting to height would have this handler
        # answer the event its own resize produces.
        self._bullets_width = 0
        self.bullets_text.bind("<Configure>", self._on_bullets_resized)

        self.advice_var = tk.StringVar(value="")
        ttk.Label(
            frame,
            textvariable=self.advice_var,
            wraplength=700,
            justify="left",
            foreground=theme.TEXT,
        ).grid(row=2, column=1, sticky="w")

    # --- Fingerprint (SHA-256) ---------------------------------------
    def _build_fingerprint_panel(self, parent, row: int) -> None:
        """
        SHA-256 is the file's unique identifier, but it means nothing to a
        first-time user, so it lives inside the İleri area rather than on the
        main screen. MD5 and SHA-1 stay one level deeper, in the detail tabs.
        """
        frame = ttk.LabelFrame(parent, text=t("trust.section.fingerprint"), padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.sha256_var = tk.StringVar(value="—")
        entry = ttk.Entry(
            frame,
            textvariable=self.sha256_var,
            font=theme.FONT_MONO,
        )
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        entry.state(["readonly"])
        self._sha256_entry = entry

        ttk.Button(
            frame,
            text=t("btn.copy"),
            width=12,
            command=lambda: self._copy_to_clipboard(self.sha256_var.get()),
        ).grid(row=0, column=1)

        ttk.Label(
            frame,
            text=t("trust.fingerprint.hint"),
            foreground=theme.MUTED,
            wraplength=820,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

    # --- Export / remember row (inside the İleri area) ----------------
    def _build_export_row(self, parent, row: int) -> None:
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.remember_btn = ttk.Button(
            frame, text=t("trust.btn.remember"), command=self._on_remember
        )
        self.export_json_btn = ttk.Button(
            frame, text=t("trust.btn.export_json"),
            command=lambda: self._on_export("json"),
        )
        self.export_html_btn = ttk.Button(
            frame, text=t("trust.btn.export_html"),
            command=lambda: self._on_export("html"),
        )

        for i, btn in enumerate(
            (self.remember_btn, self.export_json_btn, self.export_html_btn)
        ):
            btn.grid(row=0, column=1 + i, padx=(8 if i else 0, 0))
            btn.state(["disabled"])

    # --- Details notebook (inside the İleri area) --------------------
    def _build_details_notebook(self, parent, row: int) -> None:
        """Per-check detail tabs (file / hashes / VirusTotal / signature / local)."""
        nb = ttk.Notebook(parent)
        nb.grid(row=row, column=0, sticky="nsew", pady=(6, 0))
        self._details_notebook = nb

        self.file_tab = self._make_kv_tab(nb, t("trust.tab.file"))
        self.hash_tab_frame, self.hash_rows = self._make_hash_tab(nb)
        self.vt_tab = self._make_kv_tab(nb, t("trust.tab.vt"))
        self.signature_tab = self._make_kv_tab(nb, t("trust.tab.signature"))
        self.local_tab = self._make_kv_tab(nb, t("trust.tab.local"))

        nb.add(self.file_tab["frame"], text=t("trust.tab.file"))
        nb.add(self.hash_tab_frame, text=t("trust.tab.hashes"))
        nb.add(self.vt_tab["frame"], text=t("trust.tab.vt"))
        nb.add(self.signature_tab["frame"], text=t("trust.tab.signature"))
        nb.add(self.local_tab["frame"], text=t("trust.tab.local"))

    def _toggle_details(self) -> None:
        if self._details_visible:
            self._advanced_container.grid_forget()
            self._details_visible = False
            self._details_toggle_var.set(t("trust.details.show"))
        else:
            self._advanced_container.grid(row=3, column=0, sticky="nsew")
            self._details_visible = True
            self._details_toggle_var.set(t("trust.details.hide"))

    def _make_kv_tab(self, parent: ttk.Notebook, title: str) -> dict[str, Any]:
        frame = ttk.Frame(parent, padding=10)
        frame.columnconfigure(1, weight=1)
        rows: dict[str, tuple[ttk.Label, ttk.Label]] = {}
        return {"frame": frame, "rows": rows, "title": title}

    def _make_hash_tab(self, parent: ttk.Notebook) -> tuple[ttk.Frame, dict[str, ttk.Entry]]:
        """
        Holds *only* the legacy MD5 / SHA-1 digests. SHA-256 lives in
        its own card above the details panel because it is the primary
        identifier we want non-technical users to see.
        """
        frame = ttk.Frame(parent, padding=10)
        frame.columnconfigure(1, weight=1)
        ttk.Label(
            frame,
            text=t("trust.hashes.legacy_warning"),
            foreground=theme.MUTED,
            wraplength=620,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        rows: dict[str, ttk.Entry] = {}
        for i, algo in enumerate(("md5", "sha1"), start=1):
            ttk.Label(frame, text=algo.upper() + ":", font=theme.FONT_LABEL_BOLD).grid(
                row=i, column=0, sticky="w", pady=4
            )
            var = tk.StringVar(value="—")
            entry = ttk.Entry(frame, textvariable=var, font=theme.FONT_MONO_SMALL)
            entry.grid(row=i, column=1, sticky="ew", padx=(6, 6), pady=4)
            entry.state(["readonly"])
            entry._var = var  # type: ignore[attr-defined]
            ttk.Button(
                frame, text=t("btn.copy"), width=10,
                command=lambda v=var: self._copy_to_clipboard(v.get())
            ).grid(row=i, column=2, padx=(0, 0))
            rows[algo] = entry
        return frame, rows

    # ==================================================================
    # File selection
    # ==================================================================
    def _pick_file(self) -> None:
        if self._busy:
            return
        path = filedialog.askopenfilename(title=t("trust.picker.file_title"))
        if path:
            self._set_selected_path(path)

    def _set_selected_path(self, path: str) -> None:
        p = Path(path)
        if not p.exists() or not p.is_file():
            messagebox.showwarning(
                t("trust.invalid.title"),
                t("trust.invalid.body", path=path),
            )
            return
        # The controller owns "which file are we talking about"; selecting a
        # new one invalidates any in-flight scan and the previous result.
        self._controller.select(str(p))
        self._selected_path = self._controller.selected_path
        self._last_result = None
        self.file_label_var.set(
            t("trust.selected", name=p.name, path=p.resolve())
        )
        self._clear_summary()
        self._clear_technical_tabs()
        self.scan_button.state(["!disabled"])
        # Disable result-dependent buttons until a fresh scan completes
        # for this path. (Re-scan is enabled via the main scan button.)
        for btn in (self.export_json_btn, self.export_html_btn, self.remember_btn, self.rescan_btn):
            btn.state(["disabled"])

    # ==================================================================
    # Scan flow (threaded)
    # ==================================================================
    def _on_scan(self) -> None:
        session = self._controller.begin_scan()
        if session is None:
            return  # nothing selected, already busy, or shutting down
        self._set_busy(True)
        self._set_status(t("trust.status.starting", name=Path(session.path).name))
        # Clear the *whole* previous result, not just the summary: a failed
        # re-scan of the same file must not leave its old hashes, VT counts,
        # signature or local-record rows visible.
        self._last_result = None
        self._clear_summary()
        self._clear_technical_tabs()

        worker = threading.Thread(
            target=self._scan_worker, args=(session,), daemon=True
        )
        self._worker_thread = worker
        worker.start()
        # One scheduler only — _poll_queue reschedules itself while busy.
        self._schedule_poll()

    def _on_cancel(self) -> None:
        """
        Ask the running scan to stop.

        ``cancel()``, never ``shutdown()``: shutdown marks the controller torn
        down for good, so every later session would be rejected and the screen
        could never scan again. The two are one keystroke apart in this file,
        and only one of them is a cancel button.

        Cancellation is cooperative — the worker notices at the next pipeline
        stage boundary, and a VirusTotal or signature stage can take seconds.
        So this does not draw the terminal card itself. It disables the button
        and says what is happening; the card appears when the worker actually
        reports back, which is the only moment the scan is really over.
        """
        if not self._controller.is_busy:
            return
        self._controller.cancel()
        self.cancel_button.state(["disabled"])
        self._set_status(t("status.cancelling"))

    def _scan_worker(self, session) -> None:
        path = session.path
        try:
            client = self._get_vt_client()
            result = run_trust_check(
                path,
                vt_client=client,
                local_store=self._local_store,
                check_signature_flag=True,
                # The saved privacy preference decides this, not merely
                # whether a key happens to be configured.
                query_virustotal=resolve_online_checks(
                    autoquery=self._get_online_enabled(),
                    has_key=client.has_key,
                ),
                # Every queued message carries its session, so a late worker
                # cannot drive the status line of a newer scan.
                on_progress=lambda step: self._msg_queue.put(
                    ("status", (session, step))
                ),
                cancel_check=session.raise_if_cancelled,
            )
            self._msg_queue.put(("done", (session, result)))
        except ScanCancelled:
            self._msg_queue.put(("cancelled", (session, None)))
        except Exception as exc:
            log.exception("trust scan failed")
            self._msg_queue.put(("error", (session, exc)))

    def _poll_queue(self) -> None:
        """
        Drain the worker queue.

        Every branch asks the controller first: a message from a superseded
        session is **discarded completely** — it may not clear busy, touch the
        status line, change the buttons, or stop the loop. Stopping early was
        the defect: a late "cancelled" from an abandoned scan left the live
        scan's UI unmanaged and its own result stranded in the queue.
        """
        # NOTE: this method does NOT clear _poll_after_id. Only the scheduled
        # tick (_on_poll_tick) may, because it is the one that has actually
        # fired. Clearing it here orphaned the pending handle whenever a
        # caller drained the queue directly, and the orphan then ran against a
        # destroyed widget.
        terminal_handled = False
        try:
            while True:
                kind, payload = self._msg_queue.get_nowait()

                if kind == "status":
                    session, step = payload
                    if self._controller.is_current(session):
                        self._set_status(str(step))
                    continue

                session, data = payload
                if kind == "cancelled":
                    if not self._controller.deliver_cancelled(session):
                        continue        # stale: ignore entirely
                    self._show_cancelled_end_state()
                    terminal_handled = True
                elif kind == "done":
                    if not self._controller.deliver_result(session, data):
                        continue
                    self._on_done(data)
                    terminal_handled = True
                elif kind == "error":
                    if not self._controller.deliver_error(session, data):
                        continue
                    self._last_result = None
                    self._show_terminal_failure(
                        t("trust.error.headline"),
                        t("trust.error.detail", error=data),
                    )
                    self._set_status(t("trust.status.failed"))
                    messagebox.showerror(t("trust.error.title"), str(data))
                    terminal_handled = True
        except queue.Empty:
            pass

        # A worker that reached its last stage boundary before the user
        # clicked Cancel delivers a perfectly good result a moment later. The
        # controller is right to discard it — the user asked to stop — but then
        # none of the branches above fire, and without this the screen keeps
        # "Dosya taranıyor, lütfen bekleyin…" with every button disabled: a
        # finished scan that says it is still running and cannot be restarted.
        if (
            not terminal_handled
            and self._busy
            and self._controller.state is ControllerState.CANCELLED
        ):
            self._show_cancelled_end_state()
            terminal_handled = True

        if terminal_handled:
            self._set_busy(False)

        # Exactly one scheduler: never stack a second polling chain.
        if self._controller.is_busy:
            self._schedule_poll()

    def _on_poll_tick(self) -> None:
        """The scheduled entry point — the only place the handle is cleared."""
        self._poll_after_id = None
        self._poll_queue()

    def _schedule_poll(self) -> None:
        if self._poll_after_id is None:
            self._poll_after_id = self.after(120, self._on_poll_tick)

    def _set_status(self, text: str) -> None:
        """Update the status bar and remember what it says (for tests)."""
        self._status_text = text
        self._push_status(text)

    @property
    def status_text(self) -> str:
        return self._status_text

    def _cancel_scheduled_poll(self) -> None:
        """Drop a pending after() callback so it cannot fire on dead widgets."""
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:  # pragma: no cover - already torn down
                pass
            self._poll_after_id = None

    def _show_cancelled_end_state(self) -> None:
        """
        The one place that says "you cancelled this".

        Reached two ways — the worker noticed the token and reported back, or
        it finished first and the controller discarded the result — and both
        must leave the screen saying the same thing.
        """
        self._set_status(t("trust.status.cancelled"))
        self._show_terminal_failure(
            t("trust.cancelled.headline"),
            t("trust.cancelled.detail"),
            advice=t("trust.cancelled.advice"),
        )

    def _show_terminal_failure(
        self,
        headline: str,
        detail: str,
        advice: Optional[str] = None,
    ) -> None:
        """
        Replace the in-progress card with an explicit end state.

        A failed or cancelled scan must not leave the "scanning, please
        wait…" text or the previous file's evidence on screen.

        *advice* is what to do next, and it is not the same sentence in both
        cases: telling someone who deliberately pressed Cancel to "fix the
        problem" describes a failure that did not happen.

        Its default is resolved here rather than in the signature. A default
        argument is evaluated once, when the module is imported, so the
        sentence would be fixed in whatever language was active at that
        moment and would not follow a later switch.
        """
        if advice is None:
            advice = t("trust.failure.advice")
        self._clear_summary()
        self._clear_technical_tabs()
        self.headline_var.set(headline)
        self.advice_var.set(f"{detail}  {advice}")

    def rescan_path(self, path: str) -> bool:
        """
        Scan *path* specifically (e.g. a history row).

        Returns False — having started nothing and cleared the stale result —
        when the file no longer exists. The caller must not fall back to the
        previous selection: that would attach the history entry's identity to
        a completely different file.
        """
        if not Path(path).is_file():
            self._controller.rescan(path)      # moves to ERROR, clears state
            self._selected_path = None
            self._last_result = None
            self._clear_summary()
            self._clear_technical_tabs()
            self.file_label_var.set(t("trust.missing_from_history"))
            self.scan_button.state(["disabled"])
            for btn in (self.export_json_btn, self.export_html_btn,
                        self.remember_btn, self.rescan_btn):
                btn.state(["disabled"])
            return False
        self._set_selected_path(path)
        self._on_scan()
        return True

    def _clear_technical_tabs(self) -> None:
        """
        Blank every detail pane.

        Selecting a new file must not leave the previous file's hashes,
        VirusTotal counts, signature or local-record rows on screen — they
        would read as belonging to the newly selected file.
        """
        placeholder = [(t("kv.status"), t("trust.kv.not_scanned"))]
        for tab in (self.file_tab, self.vt_tab, self.signature_tab, self.local_tab):
            try:
                self._set_kv_rows(tab, placeholder)
            except Exception:  # pragma: no cover - widget already destroyed
                pass
        for entry in getattr(self, "hash_rows", {}).values():
            try:
                entry.configure(state="normal")
                entry.delete(0, "end")
                entry.configure(state="readonly")
            except Exception:  # pragma: no cover
                pass

    @property
    def is_busy(self) -> bool:
        """True while a scan is in flight (controller is authoritative)."""
        return self._controller.is_busy

    def shutdown(self) -> None:
        """
        Cancel any in-flight scan and stop accepting worker callbacks.

        Called when the window closes or the UI is about to be rebuilt (e.g.
        a language switch): the widgets a late callback would touch are about
        to disappear.
        """
        self._controller.shutdown()
        # Drop the scheduled poll first: otherwise Tk runs the after() script
        # once the widget is gone and reports `invalid command name`.
        self._cancel_scheduled_poll()
        worker = getattr(self, "_worker_thread", None)
        if worker is not None and worker.is_alive():
            # Bounded: the pipeline checks the cancel token between stages, so
            # this returns quickly. We never block the UI indefinitely.
            worker.join(timeout=5.0)
        self._busy = False

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = ["disabled"] if busy else ["!disabled"]
        self.scan_button.state(state)
        # The exact inverse of the scan button: stopping only means something
        # while something is running, and an enabled Cancel on an idle screen
        # invites a press that would silently do nothing.
        self.cancel_button.state(["!disabled"] if busy else ["disabled"])
        if not busy:
            # Re-enable strictly on the controller's verdict: a result that
            # was superseded or errored must leave every result action off.
            has_result = self._controller.can_export
            for btn in (self.rescan_btn, self.export_json_btn, self.export_html_btn, self.remember_btn):
                btn.state(["!disabled"] if has_result else ["disabled"])
            # Scan button stays usable while a file is selected.
            if self._selected_path:
                self.scan_button.state(["!disabled"])

    # ==================================================================
    # Result rendering
    # ==================================================================
    def _on_done(self, result: TrustResult) -> None:
        self._last_result = result
        self._set_status(t("trust.status.done"))

        summary = result.summary
        level = summary.risk_level.value if summary else RiskLevel.UNKNOWN.value
        color, label = risk_presentation(level)
        self._draw_badge(color, label)

        # The core decided which sentences are true; the words are chosen here,
        # at the moment of display, so a language switch is not a scan away.
        said = render_summary(summary) if summary else None
        self.headline_var.set(said.headline if said else "")

        self.bullets_text.configure(state="normal")
        self.bullets_text.delete("1.0", "end")
        if said:
            for bullet in said.bullets:
                self.bullets_text.insert("end", f"• {bullet}\n")
        self.bullets_text.configure(state="disabled")
        self._fit_bullets()
        self.advice_var.set(said.advice if said else "")

        self._render_file_info(result)
        self._render_hashes(result)
        self._render_vt(result)
        self._render_signature(result)
        self._render_local(result)

        self._record_in_history(result)

    # Enough room for the shortest summary; grown by _fit_bullets when the
    # sentences need more. Never shrunk below this, so the card does not
    # jump about between scans.
    _BULLET_LINES_MIN = 4

    def _fit_bullets(self) -> None:
        """
        Grow the bullet box to whatever the sentences actually need.

        A fixed height is a guess about how long a verdict will be, and Tk
        does not report the lines that do not fit — it stops drawing them,
        with nothing on screen to say so. At the 880-pixel minimum this window
        allows, the longest summary lost one line in Turkish and two in
        English. What goes missing is not decoration: the bullets are the
        evidence for the risk level above them, so the screen was showing a
        verdict while withholding part of the reason for it.

        Measured after the text is in place rather than estimated from
        character counts, because what matters is how the widget wrapped it at
        this width — which is also why it re-runs when the window resizes.
        """
        box = self.bullets_text
        box.update_idletasks()
        try:
            counted = box.count("1.0", "end", "displaylines")
        except tk.TclError:  # pragma: no cover - widget already gone
            return
        wrapped = counted[0] if counted else 0
        box.configure(height=max(self._BULLET_LINES_MIN, wrapped))

    def _on_bullets_resized(self, event) -> None:
        if event.width != self._bullets_width:
            self._bullets_width = event.width
            self._fit_bullets()

    def _record_in_history(self, result: TrustResult) -> None:
        if not result.summary or not result.assessment:
            return
        vt = result.vt
        sig = result.signature
        try:
            entry = make_entry(
                file_name=result.file_info.name,
                file_path=result.file_info.path,
                sha256=result.sha256,
                risk_level=result.summary.risk_level.value,
                # Words, not a key: the history file is a record of what the
                # user was told at the time, and re-rendering it later in
                # another language would rewrite that record.
                headline=render_summary(result.summary).headline,
                vt_malicious=vt.stats.malicious if (vt and vt.status == VTStatus.OK) else 0,
                vt_suspicious=vt.stats.suspicious if (vt and vt.status == VTStatus.OK) else 0,
                vt_status=vt.status.value if vt else "",
                signature_status=sig.status.value if sig else "",
            )
            self._history.add(entry)
        except HistoryStoreError as exc:
            # The scan itself succeeded, but the user must know it was not
            # recorded — otherwise the History tab silently misses runs.
            log.exception("history record failed")
            messagebox.showwarning(
                t("trust.history_fail.title"),
                t("trust.history_fail.body", error=exc),
            )
        except Exception:
            log.exception("history record failed")
        if self._on_scan_recorded is not None:
            try:
                self._on_scan_recorded()
            except Exception:
                log.exception("history refresh callback failed")

    # ------------------------------------------------------------------
    def _render_file_info(self, result: TrustResult) -> None:
        info = result.file_info
        rows = [
            (t("trust.file.name"), info.name),
            (t("trust.file.path"), info.path),
            (
                t("trust.file.size"),
                t("trust.file.size_value",
                  human=info.size_human, size=info.size_bytes),
            ),
            (t("trust.file.extension"), info.extension),
            (t("trust.file.created"), info.created_at or "—"),
            (t("trust.file.modified"), info.modified_at or "—"),
        ]
        self._set_kv_rows(self.file_tab, rows)

    def _render_hashes(self, result: TrustResult) -> None:
        # SHA-256 goes to the primary fingerprint card above; MD5 and
        # SHA-1 stay collapsed under the technical-details notebook.
        self._sha256_entry.state(["!readonly"])
        self.sha256_var.set(result.hashes.get("sha256") or "—")
        self._sha256_entry.state(["readonly"])

        for algo, entry in self.hash_rows.items():
            value = result.hashes.get(algo) or "—"
            var: tk.StringVar = entry._var  # type: ignore[attr-defined]
            entry.state(["!readonly"])
            var.set(value)
            entry.state(["readonly"])

    def _render_vt(self, result: TrustResult) -> None:
        vt = result.vt
        if vt is None:
            self._set_kv_rows(
                self.vt_tab, [(t("kv.status"), t("trust.vt.not_queried"))]
            )
            return
        if vt.status == VTStatus.NO_API_KEY:
            self._set_kv_rows(
                self.vt_tab,
                [
                    (t("kv.status"), t("trust.vt.no_key")),
                    (t("trust.vt.no_key_hint_label"), t("trust.vt.no_key_hint")),
                ],
            )
            return
        if vt.status != VTStatus.OK:
            self._set_kv_rows(
                self.vt_tab,
                [
                    (t("kv.status"), vt.status.value),
                    (t("kv.detail"), vt.message or "—"),
                ],
            )
            return
        s = vt.stats
        self._set_kv_rows(
            self.vt_tab,
            [
                (t("kv.status"), t("trust.vt.ok")),
                (t("trust.vt.malicious"), str(s.malicious)),
                (t("trust.vt.suspicious"), str(s.suspicious)),
                (t("trust.vt.harmless"), str(s.harmless)),
                (t("trust.vt.undetected"), str(s.undetected)),
                (t("trust.vt.total_engines"), str(vt.total_engines)),
                (t("trust.vt.last_analysis"), vt.last_analysis_date or "—"),
                (t("trust.vt.reputation"),
                 "—" if vt.reputation is None else str(vt.reputation)),
                (t("trust.vt.type_description"), vt.type_description or "—"),
                (t("trust.vt.meaningful_name"), vt.meaningful_name or "—"),
            ],
        )

    def _render_signature(self, result: TrustResult) -> None:
        sig = result.signature
        if sig is None:
            self._set_kv_rows(
                self.signature_tab, [(t("kv.status"), t("trust.sig.not_checked"))]
            )
            return
        key = _SIGNATURE_KEYS.get(sig.status)
        friendly = t(key) if key else sig.status.value
        rows = [
            (t("kv.status"), friendly),
            (t("trust.sig.signer"), sig.signer or "—"),
        ]
        if sig.message:
            rows.append((t("kv.detail"), sig.message))
        if sig.raw_status:
            rows.append((t("trust.sig.raw_status"), sig.raw_status))
        self._set_kv_rows(self.signature_tab, rows)

    def _render_local(self, result: TrustResult) -> None:
        local = result.local
        if local is None:
            self._set_kv_rows(
                self.local_tab,
                [(t("kv.status"), t("trust.local.not_compared"))],
            )
            return
        key = _LOCAL_KEYS.get(local.status)
        friendly = t(key) if key else local.status.value
        rows = [(t("kv.status"), friendly), (t("kv.detail"), local.message or "—")]
        if local.previous_hash:
            rows.append((t("trust.local.previous_hash"), local.previous_hash))
        if local.current_hash:
            rows.append((t("trust.local.current_hash"), local.current_hash))
        if local.record:
            rows.append((t("trust.local.first_seen"), local.record.recorded_at))
            rows.append((t("trust.local.last_seen"), local.record.last_seen_at))
        self._set_kv_rows(self.local_tab, rows)

    # ==================================================================
    # KV table helpers
    # ==================================================================
    def _set_kv_rows(self, tab: dict[str, Any], rows: list[tuple[str, str]]) -> None:
        frame: ttk.Frame = tab["frame"]
        current: dict[str, tuple[ttk.Label, ttk.Label]] = tab["rows"]
        for label, value in current.values():
            label.destroy()
            value.destroy()
        current.clear()
        for i, (label, value) in enumerate(rows):
            l = ttk.Label(frame, text=label + ":", font=theme.FONT_LABEL_BOLD)
            l.grid(row=i, column=0, sticky="nw", pady=3, padx=(0, 8))
            v = ttk.Label(frame, text=value, wraplength=680, justify="left")
            v.grid(row=i, column=1, sticky="w", pady=3)
            current[label] = (l, v)

    # ==================================================================
    # Misc actions
    # ==================================================================
    def _on_remember(self) -> None:
        if self._last_result is None or not self._last_result.sha256:
            return
        info = self._last_result.file_info
        result = self._last_result

        # Replacing a baseline destroys the only record of the previous
        # version, so the policy decides whether it may happen at all.
        decision = evaluate_baseline_request(
            local_status=(result.local.status if result.local else LocalVerifyStatus.NOT_TRACKED),
            risk_level=(result.assessment.level if result.assessment else RiskLevel.UNKNOWN),
            signature_broken=bool(
                result.signature
                and result.signature.status == SignatureStatus.HASH_MISMATCH
            ),
            # Pass the real detection counts, not just the summarised level.
            vt_malicious=(result.vt.stats.malicious if result.vt else 0),
            vt_suspicious=(result.vt.stats.suspicious if result.vt else 0),
        )
        if decision is BaselineDecision.BLOCKED:
            messagebox.showerror(
                t("trust.remember.blocked_title"), decision_prompt(decision)
            )
            return
        if decision is BaselineDecision.ALREADY_CURRENT:
            messagebox.showinfo(
                t("trust.remember.current_title"), decision_prompt(decision)
            )
            return
        if decision in (BaselineDecision.CONFIRM_REPLACE, BaselineDecision.CONFIRM_RISKY):
            title = (
                t("trust.remember.replace_title")
                if decision is BaselineDecision.CONFIRM_REPLACE
                else t("trust.remember.risky_title")
            )
            if not messagebox.askyesno(title, decision_prompt(decision)):
                return

        # Re-verify the file right before writing: the bytes we are about to
        # bless as "known good" must be the ones we actually scanned.
        try:
            current = compute_file_hashes(info.path, ("sha256",), ensure_stable=True)
        except HashError as exc:
            messagebox.showerror(
                t("trust.remember.failed_title"),
                t("trust.remember.reread_failed", error=exc),
            )
            return
        if current.get("sha256") != result.sha256:
            messagebox.showerror(
                t("trust.remember.failed_title"),
                t("trust.remember.changed_after_scan"),
            )
            return

        try:
            outcome = self._local_store.remember(
                info.path, self._last_result.sha256, info.size_bytes
            )
        except LocalStoreError as exc:
            # Only claim success when the write actually happened.
            messagebox.showerror(t("trust.remember.failed_title"), str(exc))
            return
        messagebox.showinfo(
            t("trust.remember.done_title"),
            outcome.message or t("trust.remember.done_body"),
        )
        # Refresh the Local tab so the user sees the new "Aynı dosya" state.
        self._last_result.local = self._local_store.compare(info.path, self._last_result.sha256)
        self._render_local(self._last_result)

    def _on_export(self, fmt: str) -> None:
        if self._last_result is None:
            return
        # Strip the extension from the source filename so we don't end
        # up with "setup.exe_guven_raporu.json".
        stem = Path(self._last_result.file_info.name).stem or "rapor"
        suggested = t("trust.export.filename", stem=stem) + f".{fmt}"
        path = filedialog.asksaveasfilename(
            title=t("trust.export.title"),
            defaultextension=f".{fmt}",
            initialfile=suggested,
            filetypes=[(fmt.upper(), f"*.{fmt}"), (t("trust.export.all_files"), "*.*")],
        )
        if not path:
            return
        report = self._last_result.to_report()
        try:
            if fmt == "json":
                export_json(report, path, translate=t)
            else:
                export_html(report, path, translate=t, language=get_language())
        except TrustReportError as exc:
            messagebox.showerror(t("trust.export.error_title"), str(exc))
            return
        messagebox.showinfo(
            t("trust.export.done_title"), t("trust.export.done_body", path=path)
        )

    # ==================================================================
    # Visual helpers
    # ==================================================================
    def _clear_summary(self) -> None:
        self._draw_badge(theme.MUTED, t("trust.badge.scanning"))
        self.headline_var.set(t("trust.summary.scanning"))
        self.bullets_text.configure(state="normal")
        self.bullets_text.delete("1.0", "end")
        self.bullets_text.configure(state="disabled")
        # Back to the minimum: a box still tall enough for the last scan's
        # sentences, with nothing in it, reads as something failing to load.
        self.bullets_text.configure(height=self._BULLET_LINES_MIN)
        self.advice_var.set("")
        self._sha256_entry.state(["!readonly"])
        self.sha256_var.set("—")
        self._sha256_entry.state(["readonly"])

    def _draw_badge(self, color: str, text: str) -> None:
        c = self.badge_canvas
        c.delete("all")
        c.configure(bg=self._bg(c.master))
        c.create_oval(8, 8, 50, 50, fill=color, outline=color)
        c.create_text(60, 30, text=text, anchor="w",
                      font=theme.FONT_HEADING, fill=color)

    @staticmethod
    def _bg(widget: tk.Widget) -> str:
        try:
            return ttk.Style().lookup(widget.winfo_class(), "background") or theme.SURFACE
        except tk.TclError:
            return theme.SURFACE

    def _copy_to_clipboard(self, text: str) -> None:
        if not text or text == "—":
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(t("trust.copied", count=len(text)))
