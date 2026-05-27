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

import threading
import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Optional

from core.local_verify import LocalVerifyStatus, LocalVerifyStore
from core.risk_engine import RiskLevel
from core.signature_checker import SignatureStatus
from core.trust_pipeline import TrustResult, run_trust_check
from core.trust_report import TrustReportError, export_html, export_json
from core.vt_client import VirusTotalClient, VTStatus
from core.history_manager import HistoryManager, make_entry
from utils.logger import get_logger

log = get_logger("gui.trust")


# Risk-level → (badge background, badge text)
RISK_PRESENTATION: dict[str, tuple[str, str]] = {
    RiskLevel.LOW.value:     ("#2e7d32", "Düşük Risk"),
    RiskLevel.MEDIUM.value:  ("#ef6c00", "Orta Risk"),
    RiskLevel.HIGH.value:    ("#c62828", "Yüksek Risk"),
    RiskLevel.UNKNOWN.value: ("#616161", "Bilinmiyor"),
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
    ) -> None:
        super().__init__(parent, padding=14)
        self._get_vt_client = get_vt_client
        self._local_store = local_store
        self._history = history_manager
        self._set_status = set_status
        self._on_scan_recorded = on_scan_recorded

        self._selected_path: Optional[str] = None
        self._last_result: Optional[TrustResult] = None
        self._busy = False
        self._msg_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()

        self._build()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        # Row 4 (details notebook) grows; everything above stays compact
        # so the "first show simple summary, then details" UX hierarchy
        # is preserved.
        self.rowconfigure(4, weight=1)

        self._build_drop_zone(row=0)
        self._build_summary_panel(row=1)
        self._build_fingerprint_panel(row=2)
        self._build_action_row(row=3)
        self._build_details_notebook(row=4)

    # --- Drop zone ----------------------------------------------------
    def _build_drop_zone(self, row: int) -> None:
        frame = ttk.LabelFrame(self, text="1. Dosya Seçin", padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.file_label_var = tk.StringVar(
            value="Henüz dosya seçilmedi. Sağdaki düğmeyi kullanın veya dosyayı pencereye sürükleyin."
        )
        ttk.Label(
            frame,
            textvariable=self.file_label_var,
            wraplength=820,
            justify="left",
        ).grid(row=0, column=0, sticky="ew", padx=(0, 12))

        btns = ttk.Frame(frame)
        btns.grid(row=0, column=1, sticky="e")
        ttk.Button(
            btns, text="Dosya Seç…", command=self._pick_file, style="Accent.TButton"
        ).pack(side="left")
        self.scan_button = ttk.Button(
            btns, text="Taramayı Başlat", command=self._on_scan
        )
        self.scan_button.pack(side="left", padx=(8, 0))
        self.scan_button.state(["disabled"])

        # Lightweight drag-and-drop via the windnd library if installed.
        # No hard dependency: if windnd isn't there we silently skip.
        try:
            import windnd  # type: ignore

            def _on_drop(paths: list[bytes]) -> None:
                if not paths:
                    return
                p = paths[0].decode("utf-8", errors="replace")
                self._set_selected_path(p)

            windnd.hook_dropfiles(self, func=_on_drop)
        except Exception:
            pass

    # --- Summary ------------------------------------------------------
    def _build_summary_panel(self, row: int) -> None:
        frame = ttk.LabelFrame(self, text="2. Sonuç Özeti", padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(1, weight=1)

        self.badge_canvas = tk.Canvas(
            frame, width=140, height=58, highlightthickness=0, bg=self._bg(frame)
        )
        self.badge_canvas.grid(row=0, column=0, sticky="w", padx=(0, 16), rowspan=3)
        self._draw_badge("#9e9e9e", "—")

        self.headline_var = tk.StringVar(
            value="Bir dosya seçip “Taramayı Başlat” düğmesine bastığınızda sonuç burada görünecek."
        )
        ttk.Label(
            frame,
            textvariable=self.headline_var,
            font=("Segoe UI", 11, "bold"),
            wraplength=700,
            justify="left",
        ).grid(row=0, column=1, sticky="w")

        self.bullets_text = tk.Text(
            frame,
            height=4,
            wrap="word",
            bd=0,
            background=self._bg(frame),
            font=("Segoe UI", 10),
        )
        self.bullets_text.grid(row=1, column=1, sticky="ew", pady=(8, 8))
        self.bullets_text.configure(state="disabled")

        self.advice_var = tk.StringVar(value="")
        ttk.Label(
            frame,
            textvariable=self.advice_var,
            wraplength=700,
            justify="left",
            foreground="#444",
        ).grid(row=2, column=1, sticky="w")

    # --- Fingerprint (SHA-256) ---------------------------------------
    def _build_fingerprint_panel(self, row: int) -> None:
        """
        Beginner UX rule: SHA-256 is the *main* visible identifier. It
        gets its own card right under the summary; MD5 and SHA-1 stay
        hidden inside the collapsible "Teknik Detaylar" notebook below.
        """
        frame = ttk.LabelFrame(self, text="3. Dosya Parmak İzi (SHA-256)", padding=14)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.sha256_var = tk.StringVar(value="—")
        entry = ttk.Entry(
            frame,
            textvariable=self.sha256_var,
            font=("Consolas", 10),
        )
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        entry.state(["readonly"])
        self._sha256_entry = entry

        ttk.Button(
            frame,
            text="Kopyala",
            width=12,
            command=lambda: self._copy_to_clipboard(self.sha256_var.get()),
        ).grid(row=0, column=1)

        ttk.Label(
            frame,
            text=(
                "Bu kod dosyanın benzersiz parmak izidir. "
                "Aynı kod = aynı dosya. Farklı kod = dosya değişmiş demektir."
            ),
            foreground="#666",
            wraplength=820,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

    # --- Action row ---------------------------------------------------
    def _build_action_row(self, row: int) -> None:
        frame = ttk.Frame(self)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.rescan_btn = ttk.Button(frame, text="Tekrar Tara", command=self._on_scan)
        self.remember_btn = ttk.Button(
            frame, text="Parmak İzini Kaydet", command=self._on_remember
        )
        self.export_json_btn = ttk.Button(
            frame, text="Raporu Kaydet (JSON)", command=lambda: self._on_export("json")
        )
        self.export_html_btn = ttk.Button(
            frame, text="Raporu Kaydet (HTML)", command=lambda: self._on_export("html")
        )

        for i, btn in enumerate(
            (self.rescan_btn, self.remember_btn, self.export_json_btn, self.export_html_btn)
        ):
            btn.grid(row=0, column=1 + i, padx=(8 if i else 0, 0))
            btn.state(["disabled"])

    # --- Details notebook --------------------------------------------
    def _build_details_notebook(self, row: int) -> None:
        """
        Collapsed by default to keep the first screen distraction-free
        for non-technical users. The toggle button is the only thing
        visible until the user explicitly asks for the details.
        """
        wrapper = ttk.Frame(self)
        wrapper.grid(row=row, column=0, sticky="nsew")
        wrapper.columnconfigure(0, weight=1)
        wrapper.rowconfigure(1, weight=1)

        header = ttk.Frame(wrapper)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text="Teknik Detaylar",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        self._details_toggle_var = tk.StringVar(value="Göster ▾")
        self._details_toggle_btn = ttk.Button(
            header,
            textvariable=self._details_toggle_var,
            width=12,
            command=self._toggle_details,
        )
        self._details_toggle_btn.grid(row=0, column=1, sticky="e")

        nb = ttk.Notebook(wrapper)
        # NOT gridded yet — collapsed state. _toggle_details() lays it
        # out when the user clicks the button.
        self._details_notebook = nb
        self._details_visible = False

        self.file_tab = self._make_kv_tab(nb, "Dosya")
        self.hash_tab_frame, self.hash_rows = self._make_hash_tab(nb)
        self.vt_tab = self._make_kv_tab(nb, "VirusTotal")
        self.signature_tab = self._make_kv_tab(nb, "Dijital İmza")
        self.local_tab = self._make_kv_tab(nb, "Yerel Kayıt")

        nb.add(self.file_tab["frame"], text="Dosya Bilgileri")
        nb.add(self.hash_tab_frame, text="Hash (MD5 / SHA-1)")
        nb.add(self.vt_tab["frame"], text="VirusTotal")
        nb.add(self.signature_tab["frame"], text="Dijital İmza")
        nb.add(self.local_tab["frame"], text="Yerel Kayıt")

    def _toggle_details(self) -> None:
        if self._details_visible:
            self._details_notebook.grid_forget()
            self._details_visible = False
            self._details_toggle_var.set("Göster ▾")
        else:
            self._details_notebook.grid(row=1, column=0, sticky="nsew")
            self._details_visible = True
            self._details_toggle_var.set("Gizle ▴")

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
            text=(
                "MD5 ve SHA-1 eski hash algoritmalarıdır ve kriptografik açıdan "
                "kırılmış sayılırlar. Yalnızca eski yazılımlarla uyumluluk için "
                "burada gösteriliyorlar. Asıl parmak izi yukarıdaki SHA-256'dır."
            ),
            foreground="#666",
            wraplength=620,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        rows: dict[str, ttk.Entry] = {}
        for i, algo in enumerate(("md5", "sha1"), start=1):
            ttk.Label(frame, text=algo.upper() + ":", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="w", pady=4
            )
            var = tk.StringVar(value="—")
            entry = ttk.Entry(frame, textvariable=var, font=("Consolas", 9))
            entry.grid(row=i, column=1, sticky="ew", padx=(6, 6), pady=4)
            entry.state(["readonly"])
            entry._var = var  # type: ignore[attr-defined]
            ttk.Button(
                frame, text="Kopyala", width=10,
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
        path = filedialog.askopenfilename(title="Kontrol Edilecek Dosyayı Seçin")
        if path:
            self._set_selected_path(path)

    def _set_selected_path(self, path: str) -> None:
        p = Path(path)
        if not p.exists() or not p.is_file():
            messagebox.showwarning(
                "Geçersiz Dosya",
                f"Bu yol bir dosyaya işaret etmiyor:\n{path}",
            )
            return
        self._selected_path = str(p.resolve())
        self.file_label_var.set(
            f"Seçili dosya: {p.name}\n{p.resolve()}"
        )
        self.scan_button.state(["!disabled"])
        # Disable result-dependent buttons until a fresh scan completes
        # for this path. (Re-scan is enabled via the main scan button.)
        for btn in (self.export_json_btn, self.export_html_btn, self.remember_btn, self.rescan_btn):
            btn.state(["disabled"])

    # ==================================================================
    # Scan flow (threaded)
    # ==================================================================
    def _on_scan(self) -> None:
        if self._busy or not self._selected_path:
            return
        path = self._selected_path
        self._set_busy(True)
        self._set_status(f"Tarama başlatılıyor — {Path(path).name}")
        self._clear_summary()

        worker = threading.Thread(
            target=self._scan_worker, args=(path,), daemon=True
        )
        worker.start()
        self.after(120, self._poll_queue)

    def _scan_worker(self, path: str) -> None:
        try:
            client = self._get_vt_client()
            result = run_trust_check(
                path,
                vt_client=client,
                local_store=self._local_store,
                check_signature_flag=True,
                query_virustotal=client.has_key,
                on_progress=lambda step: self._msg_queue.put(("status", step)),
            )
            self._msg_queue.put(("done", result))
        except Exception as exc:
            log.exception("trust scan failed")
            self._msg_queue.put(("error", exc))

    def _poll_queue(self) -> None:
        drained = 0
        try:
            while True:
                kind, payload = self._msg_queue.get_nowait()
                drained += 1
                if kind == "status":
                    self._set_status(str(payload))
                elif kind == "done":
                    self._on_done(payload)
                    self._set_busy(False)
                    return
                elif kind == "error":
                    self._set_busy(False)
                    messagebox.showerror("Tarama Hatası", str(payload))
                    self._set_status("Hata.")
                    return
        except queue.Empty:
            pass

        if self._busy:
            self.after(120, self._poll_queue)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = ["disabled"] if busy else ["!disabled"]
        self.scan_button.state(state)
        if not busy:
            # Re-enable depends on whether we now have a result.
            has_result = self._last_result is not None
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
        self._set_status("Tamamlandı.")

        summary = result.summary
        level = summary.risk_level.value if summary else RiskLevel.UNKNOWN.value
        color, label = RISK_PRESENTATION.get(level, RISK_PRESENTATION[RiskLevel.UNKNOWN.value])
        self._draw_badge(color, label)

        self.headline_var.set(summary.headline if summary else "")

        self.bullets_text.configure(state="normal")
        self.bullets_text.delete("1.0", "end")
        if summary:
            for bullet in summary.bullets:
                self.bullets_text.insert("end", f"• {bullet}\n")
        self.bullets_text.configure(state="disabled")
        self.advice_var.set(summary.advice if summary else "")

        self._render_file_info(result)
        self._render_hashes(result)
        self._render_vt(result)
        self._render_signature(result)
        self._render_local(result)

        self._record_in_history(result)

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
                headline=result.summary.headline,
                vt_malicious=vt.stats.malicious if (vt and vt.status == VTStatus.OK) else 0,
                vt_suspicious=vt.stats.suspicious if (vt and vt.status == VTStatus.OK) else 0,
                vt_status=vt.status.value if vt else "",
                signature_status=sig.status.value if sig else "",
            )
            self._history.add(entry)
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
            ("Dosya Adı", info.name),
            ("Tam Yol", info.path),
            ("Boyut", info.size_human + f"  ({info.size_bytes} bayt)"),
            ("Uzantı", info.extension),
            ("Oluşturulma", info.created_at or "—"),
            ("Son Değişiklik", info.modified_at or "—"),
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
            self._set_kv_rows(self.vt_tab, [("Durum", "Sorgu yapılmadı (kapalı)")])
            return
        if vt.status == VTStatus.NO_API_KEY:
            self._set_kv_rows(
                self.vt_tab,
                [
                    ("Durum", "API anahtarı ayarlanmamış"),
                    ("Bilgi", "Ayarlar sekmesinden VirusTotal API anahtarınızı girebilirsiniz."),
                ],
            )
            return
        if vt.status != VTStatus.OK:
            self._set_kv_rows(
                self.vt_tab,
                [
                    ("Durum", vt.status.value),
                    ("Açıklama", vt.message or "—"),
                ],
            )
            return
        s = vt.stats
        self._set_kv_rows(
            self.vt_tab,
            [
                ("Durum", "Sorgu başarılı"),
                ("Zararlı (malicious)", str(s.malicious)),
                ("Şüpheli (suspicious)", str(s.suspicious)),
                ("Temiz (harmless)", str(s.harmless)),
                ("Algılanmadı (undetected)", str(s.undetected)),
                ("Toplam motor", str(vt.total_engines)),
                ("Son analiz", vt.last_analysis_date or "—"),
                ("İtibar (reputation)", "—" if vt.reputation is None else str(vt.reputation)),
                ("Dosya türü tahmini", vt.type_description or "—"),
                ("Bilinen isim", vt.meaningful_name or "—"),
            ],
        )

    def _render_signature(self, result: TrustResult) -> None:
        sig = result.signature
        if sig is None:
            self._set_kv_rows(self.signature_tab, [("Durum", "Kontrol yapılmadı")])
            return
        friendly = {
            SignatureStatus.SIGNED_VALID:    "İmzalı (geçerli)",
            SignatureStatus.SIGNED_INVALID:  "İmzalı (doğrulanamadı)",
            SignatureStatus.UNSIGNED:        "İmza yok",
            SignatureStatus.UNKNOWN:         "Belirsiz",
            SignatureStatus.UNSUPPORTED:     "Desteklenmiyor (yalnızca Windows)",
            SignatureStatus.ERROR:           "Hata",
        }.get(sig.status, sig.status.value)
        rows = [
            ("Durum", friendly),
            ("İmzalayan", sig.signer or "—"),
        ]
        if sig.message:
            rows.append(("Açıklama", sig.message))
        if sig.raw_status:
            rows.append(("Ham durum", sig.raw_status))
        self._set_kv_rows(self.signature_tab, rows)

    def _render_local(self, result: TrustResult) -> None:
        local = result.local
        if local is None:
            self._set_kv_rows(
                self.local_tab,
                [("Durum", "Yerel karşılaştırma yapılmadı")],
            )
            return
        friendly = {
            LocalVerifyStatus.SAME:        "Aynı dosya",
            LocalVerifyStatus.CHANGED:     "Değişmiş dosya!",
            LocalVerifyStatus.NEW:         "Yeni kayıt oluşturuldu",
            LocalVerifyStatus.NOT_TRACKED: "Kayıt bulunamadı",
        }.get(local.status, local.status.value)
        rows = [("Durum", friendly), ("Açıklama", local.message or "—")]
        if local.previous_hash:
            rows.append(("Önceki SHA-256", local.previous_hash))
        if local.current_hash:
            rows.append(("Şimdiki SHA-256", local.current_hash))
        if local.record:
            rows.append(("İlk kayıt", local.record.recorded_at))
            rows.append(("Son güncelleme", local.record.last_seen_at))
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
            l = ttk.Label(frame, text=label + ":", font=("Segoe UI", 9, "bold"))
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
        outcome = self._local_store.remember(info.path, self._last_result.sha256, info.size_bytes)
        messagebox.showinfo(
            "Parmak izi kaydedildi",
            outcome.message
            or "Yerel kayıt güncellendi. Bu dosyayı ileride taradığınızda değişip değişmediği gösterilecek.",
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
        suggested = f"{stem}_guven_raporu.{fmt}"
        path = filedialog.asksaveasfilename(
            title="Raporu Kaydet",
            defaultextension=f".{fmt}",
            initialfile=suggested,
            filetypes=[(fmt.upper(), f"*.{fmt}"), ("Tüm dosyalar", "*.*")],
        )
        if not path:
            return
        report = self._last_result.to_report()
        try:
            if fmt == "json":
                export_json(report, path)
            else:
                export_html(report, path)
        except TrustReportError as exc:
            messagebox.showerror("Rapor Hatası", str(exc))
            return
        messagebox.showinfo("Rapor Kaydedildi", f"Rapor şu dosyaya yazıldı:\n{path}")

    # ==================================================================
    # Visual helpers
    # ==================================================================
    def _clear_summary(self) -> None:
        self._draw_badge("#9e9e9e", "Taranıyor…")
        self.headline_var.set("Dosya taranıyor, lütfen bekleyin…")
        self.bullets_text.configure(state="normal")
        self.bullets_text.delete("1.0", "end")
        self.bullets_text.configure(state="disabled")
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
                      font=("Segoe UI", 11, "bold"), fill=color)

    @staticmethod
    def _bg(widget: tk.Widget) -> str:
        try:
            return ttk.Style().lookup(widget.winfo_class(), "background") or "#ffffff"
        except tk.TclError:
            return "#ffffff"

    def _copy_to_clipboard(self, text: str) -> None:
        if not text or text == "—":
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Hash panoya kopyalandı ({len(text)} karakter).")
