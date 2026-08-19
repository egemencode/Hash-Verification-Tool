"""
History tab — read-only view of past trust scans.

Backed by :class:`core.history_manager.HistoryManager`. The Trust-Check
view calls ``refresh()`` after each new scan so the user always sees
the latest run at the top.

Every label here goes through :func:`gui.i18n.t`. The column values in
particular are computed per row rather than stored, so the lookup has to
happen at render time — a table built once at import would freeze whichever
language happened to be active when the module was first imported.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional

from core.history_manager import HistoryEntry, HistoryManager, HistoryStoreError
from core.risk_engine import RiskLevel
from gui import theme
from gui.i18n import t


_LEVEL_COLOR = {level.value: theme.risk_colour(level.value) for level in RiskLevel}


def level_label(level: str) -> str:
    """Risk level as a table cell — the short register, without "risk"."""
    if level in {lv.value for lv in RiskLevel}:
        return t(f"risk.level.{level}")
    return level or "—"


def signature_label(raw: str) -> str:
    """
    The signature column's own vocabulary.

    Deliberately not shared with the Trust-Check screen's signature panel:
    this column summarises into five buckets and has one line to do it in,
    while the panel distinguishes eight states and can afford a sentence.
    """
    known = {
        "signed_valid",
        "signed_invalid",
        "unsigned",
        "error",
        "unknown",
    }
    if raw in known:
        return t(f"history.sig.{raw}")
    if raw in ("unsupported", ""):
        return "—"
    return raw


class HistoryView(ttk.Frame):
    def __init__(
        self,
        parent: ttk.Notebook,
        history_manager: HistoryManager,
        *,
        on_rescan_request: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(parent, padding=14)
        self._history = history_manager
        self._on_rescan_request = on_rescan_request
        self._build()
        self.refresh()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Label(
            header,
            text=t("history.header"),
            font=theme.FONT_UI_BOLD,
        ).pack(side="left")

        btns = ttk.Frame(header)
        btns.pack(side="right")
        ttk.Button(btns, text=t("history.btn.refresh"), command=self.refresh).pack(side="left")
        ttk.Button(btns, text=t("history.btn.clear"), command=self._on_clear).pack(side="left", padx=(8, 0))

        self.tree = ttk.Treeview(
            self,
            columns=("scanned_at", "file_name", "risk", "vt", "signature", "path"),
            show="headings",
            height=18,
        )
        for col, width, anchor in (
            ("scanned_at", 150, "w"),
            ("file_name", 200, "w"),
            ("risk", 90, "center"),
            ("vt", 110, "center"),
            ("signature", 160, "w"),
            ("path", 400, "w"),
        ):
            self.tree.heading(col, text=t(f"history.col.{col}"))
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "path"))

        for level, color in _LEVEL_COLOR.items():
            self.tree.tag_configure(f"risk-{level}", foreground=color)

        self.tree.grid(row=1, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind("<Double-1>", self._on_double_click)

        self.empty_label = ttk.Label(
            self, text=t("history.empty"), foreground=theme.MUTED
        )

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        entries = self._history.all()
        self.tree.delete(*self.tree.get_children())
        if not entries:
            self.empty_label.grid(row=1, column=0, sticky="n", pady=20)
            return
        self.empty_label.grid_forget()
        for e in entries:
            self.tree.insert(
                "",
                "end",
                values=(
                    e.scanned_at,
                    e.file_name,
                    level_label(e.risk_level),
                    _vt_label(e),
                    signature_label(e.signature_status),
                    e.file_path,
                ),
                tags=(f"risk-{e.risk_level}",),
            )

    # ------------------------------------------------------------------
    def _on_clear(self) -> None:
        if not messagebox.askyesno(
            t("history.clear.title"),
            t("history.clear.question"),
        ):
            return
        try:
            self._history.clear()
        except HistoryStoreError as exc:
            # Do not blank the in-memory list if the disk write failed —
            # tell the user the history is still on disk.
            messagebox.showerror(t("history.clear.failed_title"), str(exc))
            self.refresh()
            return
        self.refresh()

    def _on_double_click(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if not sel or self._on_rescan_request is None:
            return
        values = self.tree.item(sel[0], "values")
        if len(values) < 6:
            return
        path = values[5]
        self._on_rescan_request(str(path))


def _vt_label(entry: HistoryEntry) -> str:
    """Human-readable VirusTotal column value."""
    if entry.vt_status == "ok":
        if entry.vt_malicious == 0 and entry.vt_suspicious == 0:
            return t("history.vt.clean")
        parts = []
        if entry.vt_malicious:
            parts.append(t("history.vt.malicious", count=entry.vt_malicious))
        if entry.vt_suspicious:
            parts.append(t("history.vt.suspicious", count=entry.vt_suspicious))
        return ", ".join(parts)
    if entry.vt_status == "not_found":
        return t("history.vt.not_found")
    if entry.vt_status == "no_api_key":
        return t("history.vt.no_key")
    if entry.vt_status in ("network_error", "unauthorized", "rate_limited", "error"):
        return t("history.vt.unavailable")
    return "—"
