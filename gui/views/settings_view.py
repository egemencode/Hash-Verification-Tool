"""
Settings tab — VirusTotal key, history limit, language preference.

The legacy "Settings → Language" menu still works; this tab is just a
discoverable surface so users do not have to know about menus.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional

from core.task_runner import CANCELLED, DONE, ERROR, TaskRunner
from core.vt_client import VirusTotalClient, VTStatus
from gui import theme
from gui.i18n import SUPPORTED_LANGUAGES, t
from utils.settings import AppSettings, SettingsError


class SettingsView(ttk.Frame):
    def __init__(
        self,
        parent: ttk.Notebook,
        settings: AppSettings,
        *,
        on_settings_changed: Callable[[AppSettings], None],
    ) -> None:
        super().__init__(parent, padding=18)
        # Edit a DRAFT: the live settings object (and the VirusTotal client
        # built from it) must not change until the write to disk succeeds.
        self._live_settings = settings
        self._settings = settings.copy_for_edit()
        self._on_settings_changed = on_settings_changed
        # "Test Key" used to open a raw thread and call back into Tk from it.
        # See core/task_runner.py for what that cost.
        self._key_test = TaskRunner(label="key-test")
        self._poll_after_id: Optional[str] = None
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        self.columnconfigure(1, weight=1)

        # --- VirusTotal -------------------------------------------------
        vt_frame = ttk.LabelFrame(self, text="VirusTotal", padding=14)
        vt_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        vt_frame.columnconfigure(1, weight=1)

        ttk.Label(
            vt_frame,
            # The privacy sentence is substituted rather than concatenated so
            # the surrounding paragraph can put it where its own grammar needs
            # it; not every language keeps the same sentence order.
            text=t("settings.vt.intro", privacy=t("privacy.notice")),
            justify="left",
            foreground=theme.TEXT,
            wraplength=720,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(vt_frame, text=t("settings.vt.api_key")).grid(row=1, column=0, sticky="w", pady=(0, 4))
        self.api_key_var = tk.StringVar(value=self._settings.virustotal_api_key)
        self._api_entry = ttk.Entry(
            vt_frame, textvariable=self.api_key_var, show="*", font=theme.FONT_MONO
        )
        self._api_entry.grid(row=1, column=1, sticky="ew", padx=(10, 10), pady=(0, 4))

        self._show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            vt_frame, text=t("settings.vt.show"), variable=self._show_var, command=self._toggle_visibility
        ).grid(row=1, column=2, sticky="w", pady=(0, 4))

        self.autoquery_var = tk.BooleanVar(value=self._settings.virustotal_autoquery)
        ttk.Checkbutton(
            vt_frame,
            text=t("settings.vt.autoquery"),
            variable=self.autoquery_var,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

        # Windows integration. Off until asked for: this one writes to the
        # shell, which is the user's system rather than the app's own.
        self.shell_menu_var = tk.BooleanVar(value=self._settings.shell_context_menu)
        ttk.Checkbutton(
            vt_frame,
            text=t("settings.shell.menu"),
            variable=self.shell_menu_var,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        btns = ttk.Frame(vt_frame)
        btns.grid(row=5, column=0, columnspan=3, sticky="e", pady=(12, 0))
        # Leftmost, and deliberately far from the accented "Kaydet": the only
        # destructive control on this screen should not sit under the button
        # the user reaches for by habit.
        self.remove_key_button = ttk.Button(
            btns, text=t("settings.vt.remove"), command=self._on_remove_key
        )
        self.remove_key_button.pack(side="left")
        ttk.Button(btns, text=t("settings.vt.test"), command=self._on_test).pack(
            side="left", padx=(10, 0)
        )
        ttk.Button(btns, text=t("settings.btn.save"), command=self._on_save,
                   style="Accent.TButton").pack(
            side="left", padx=(10, 0)
        )

        self.test_status_var = tk.StringVar(value="")
        ttk.Label(vt_frame, textvariable=self.test_status_var, foreground=theme.TEXT).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )

        # --- History ----------------------------------------------------
        hist_frame = ttk.LabelFrame(self, text=t("settings.history.title"), padding=14)
        hist_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        ttk.Label(hist_frame, text=t("settings.history.limit")).grid(
            row=0, column=0, sticky="w"
        )
        self.history_limit_var = tk.IntVar(value=self._settings.history_limit)
        ttk.Spinbox(
            hist_frame, from_=5, to=500, increment=5,
            textvariable=self.history_limit_var, width=8
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

        # --- Language ---------------------------------------------------
        lang_frame = ttk.LabelFrame(self, text=t("settings.language.title"), padding=14)
        lang_frame.grid(row=2, column=0, columnspan=3, sticky="ew")
        self.language_var = tk.StringVar(value=self._settings.language)
        for code in SUPPORTED_LANGUAGES:
            # Shown in their own language so a user can find theirs without
            # already being able to read the current one.
            label = t(f"menu.language.{code}")
            ttk.Radiobutton(
                lang_frame, text=label, value=code, variable=self.language_var
            ).pack(side="left", padx=(0, 12))

        ttk.Label(
            lang_frame,
            text=t("settings.language.hint"),
            foreground=theme.MUTED,
        ).pack(side="left", padx=(10, 0))

    # ------------------------------------------------------------------
    def _toggle_visibility(self) -> None:
        self._api_entry.configure(show="" if self._show_var.get() else "*")

    def _on_save(self) -> None:
        self._settings.virustotal_api_key = self.api_key_var.get().strip()
        self._settings.virustotal_autoquery = bool(self.autoquery_var.get())
        self._settings.shell_context_menu = bool(self.shell_menu_var.get())
        try:
            limit = int(self.history_limit_var.get())
        except (tk.TclError, ValueError):
            limit = 50
        # Clamp to the same range the Spinbox enforces, in case the user
        # typed something out of bounds manually.
        self._settings.history_limit = max(5, min(500, limit))
        self._settings.language = self.language_var.get()
        try:
            self._settings.save()
        except SettingsError as exc:
            # Never claim success on a failed/insecure write, and never let a
            # failed attempt leak into the running configuration: rebuild the
            # draft from the still-authoritative live settings.
            self._settings = self._live_settings.copy_for_edit()
            messagebox.showerror(t("settings.save.failed_title"), str(exc))
            return
        # Only now does the draft become the live configuration.
        self._live_settings = self._settings
        self._on_settings_changed(self._settings)
        self._settings = self._live_settings.copy_for_edit()
        messagebox.showinfo(
            t("settings.save.done_title"), t("settings.save.done_body")
        )

    def _on_remove_key(self) -> None:
        """
        Delete the stored API key — the only path in the UI that can.

        Emptying the field and saving is not equivalent. An ordinary save
        deliberately preserves a token it could not decrypt, because treating
        "undecryptable" as "absent" once destroyed a user's only copy. That is
        the right default, but it left the user whose DPAPI context changed
        (a different Windows account, a restored profile) with a key they could
        neither use nor get rid of — while the warning the application itself
        raises told them to choose "Anahtarı Kaldır".
        """
        if not messagebox.askyesno(
            t("settings.remove.title"),
            t("settings.remove.question"),
            icon="warning",
            default="no",
        ):
            return

        self._settings.clear_api_key()
        try:
            self._settings.save()
        except SettingsError as exc:
            # Same discipline as _on_save: a failed write must not leak into
            # the running configuration, and must never be reported as done.
            self._settings = self._live_settings.copy_for_edit()
            messagebox.showerror(t("settings.remove.failed_title"), str(exc))
            return

        self._live_settings = self._settings
        self.api_key_var.set("")
        self.test_status_var.set(t("settings.remove.status"))
        self._on_settings_changed(self._settings)
        self._settings = self._live_settings.copy_for_edit()
        messagebox.showinfo(
            t("settings.remove.done_title"), t("settings.remove.done_body")
        )

    def _on_test(self) -> None:
        key = self.api_key_var.get().strip()
        if not key:
            self.test_status_var.set(t("settings.test.no_key"))
            return
        self.test_status_var.set(t("settings.test.running"))

        def worker(task) -> object:
            client = VirusTotalClient(api_key=key, timeout=10.0)
            # Use the canonical empty-string SHA-256 as a known-good hash.
            empty_sha256 = (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            return client.lookup_hash(empty_sha256)

        # Pressing Test again supersedes the lookup in flight. The one being
        # replaced cannot be interrupted mid-request, but its answer is
        # refused on arrival — otherwise the slower of the two writes the
        # screen and the user reads a verdict about a key they have already
        # corrected.
        if self._key_test.submit(worker) is not None:
            self._schedule_poll()

    # ------------------------------------------------------------------
    def _schedule_poll(self) -> None:
        """One scheduler only: never stack a second polling chain."""
        if self._poll_after_id is None:
            self._poll_after_id = self.after(120, self._on_poll_tick)

    def _on_poll_tick(self) -> None:
        self._poll_after_id = None
        self._poll_key_test()

    def _poll_key_test(self) -> None:
        """
        Deliver the answer on the UI thread, at a moment we chose.

        The worker no longer calls ``after()`` itself. Tkinter refuses that
        from another thread unless the main loop happens to be running, and on
        a window that has already been destroyed it raises inside the worker,
        where the exception is printed and then ignored by everything.
        """
        result = self._key_test.drain_current()
        if result is not None:
            if result.kind == DONE:
                self._on_test_done(result.payload)
            elif result.kind == ERROR:
                self.test_status_var.set(
                    t("settings.test.error", error=result.payload)
                )
            elif result.kind == CANCELLED:
                # Superseded or torn down: the screen belongs to whatever
                # replaced this, so say nothing rather than overwrite it.
                pass
        if self._key_test.busy:
            self._schedule_poll()

    def _cancel_scheduled_poll(self) -> None:
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:  # pragma: no cover - already torn down
                pass
            self._poll_after_id = None

    def shutdown(self) -> None:
        """Stop the key test and its scheduler; safe to call more than once."""
        self._cancel_scheduled_poll()
        self._key_test.shutdown(timeout=5.0)

    def destroy(self) -> None:  # type: ignore[override]
        # Self-contained on purpose. This view is destroyed two ways — the
        # window closing and the notebook being rebuilt for a language switch
        # — and a teardown that has to be remembered at each call site is one
        # that eventually is not.
        self.shutdown()
        super().destroy()

    def _on_test_done(self, result) -> None:
        status_messages = {
            VTStatus.OK:            t("settings.test.ok"),
            VTStatus.NOT_FOUND:     t("settings.test.not_found"),
            VTStatus.UNAUTHORIZED:  t("settings.test.unauthorized"),
            VTStatus.RATE_LIMITED:  t("settings.test.rate_limited"),
            VTStatus.NETWORK_ERROR: t("settings.test.network_error"),
            VTStatus.NO_API_KEY:    t("settings.test.missing"),
            VTStatus.ERROR:         t("settings.test.error", error=result.message),
        }
        self.test_status_var.set(status_messages.get(result.status, result.message))
