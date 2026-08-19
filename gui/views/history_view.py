"""
History tab — read-only view of past trust scans.

Backed by :class:`core.history_manager.HistoryManager`. The Trust-Check
view calls ``refresh()`` after each new scan so the user always sees
the latest run at the top.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional

from core.history_manager import HistoryEntry, HistoryManager, HistoryStoreError
from core.risk_engine import RiskLevel
from gui import theme


_LEVEL_LABEL = {
    RiskLevel.LOW.value:     "Düşük",
    RiskLevel.MEDIUM.value:  "Orta",
    RiskLevel.HIGH.value:    "Yüksek",
    RiskLevel.UNKNOWN.value: "Bilinmiyor",
}
_LEVEL_COLOR = {level.value: theme.risk_colour(level.value) for level in RiskLevel}


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
            text="Son taranan dosyalar (yeniden eskiye). Yeniden taramak için satıra çift tıklayın.",
            font=theme.FONT_UI_BOLD,
        ).pack(side="left")

        btns = ttk.Frame(header)
        btns.pack(side="right")
        ttk.Button(btns, text="Yenile", command=self.refresh).pack(side="left")
        ttk.Button(btns, text="Geçmişi Temizle", command=self._on_clear).pack(side="left", padx=(8, 0))

        self.tree = ttk.Treeview(
            self,
            columns=("scanned_at", "file_name", "risk", "vt", "signature", "path"),
            show="headings",
            height=18,
        )
        for col, label, width, anchor in (
            ("scanned_at", "Tarih", 150, "w"),
            ("file_name", "Dosya", 200, "w"),
            ("risk", "Risk", 90, "center"),
            ("vt", "VirusTotal", 110, "center"),
            ("signature", "İmza", 160, "w"),
            ("path", "Yol", 400, "w"),
        ):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "path"))

        for level, color in _LEVEL_COLOR.items():
            self.tree.tag_configure(f"risk-{level}", foreground=color)

        self.tree.grid(row=1, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind("<Double-1>", self._on_double_click)

        self.empty_label = ttk.Label(
            self, text="Henüz tarama yapılmadı.", foreground=theme.MUTED
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
                    _LEVEL_LABEL.get(e.risk_level, e.risk_level or "—"),
                    _vt_label(e),
                    _signature_label(e.signature_status),
                    e.file_path,
                ),
                tags=(f"risk-{e.risk_level}",),
            )

    # ------------------------------------------------------------------
    def _on_clear(self) -> None:
        if not messagebox.askyesno(
            "Geçmişi Temizle",
            "Tüm tarama geçmişini silmek istediğinize emin misiniz?",
        ):
            return
        try:
            self._history.clear()
        except HistoryStoreError as exc:
            # Do not blank the in-memory list if the disk write failed —
            # tell the user the history is still on disk.
            messagebox.showerror("Geçmiş temizlenemedi", str(exc))
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


def _signature_label(raw: str) -> str:
    return {
        "signed_valid":   "İmzalı (geçerli)",
        "signed_invalid": "İmzalı (geçersiz)",
        "unsigned":       "İmza yok",
        "unsupported":    "—",
        "error":          "Hata",
        "unknown":        "Belirsiz",
        "":               "—",
    }.get(raw, raw)


def _vt_label(entry: HistoryEntry) -> str:
    """Human-readable VirusTotal column value."""
    if entry.vt_status == "ok":
        if entry.vt_malicious == 0 and entry.vt_suspicious == 0:
            return "Temiz işaret yok"
        parts = []
        if entry.vt_malicious:
            parts.append(f"{entry.vt_malicious} zararlı")
        if entry.vt_suspicious:
            parts.append(f"{entry.vt_suspicious} şüpheli")
        return ", ".join(parts)
    if entry.vt_status == "not_found":
        return "Bulunamadı"
    if entry.vt_status == "no_api_key":
        return "Anahtar yok"
    if entry.vt_status in ("network_error", "unauthorized", "rate_limited", "error"):
        return "Sorgulanamadı"
    return "—"
