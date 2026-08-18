"""
Settings tab — VirusTotal key, history limit, language preference.

The legacy "Settings → Language" menu still works; this tab is just a
discoverable surface so users do not have to know about menus.
"""

from __future__ import annotations

import tkinter as tk
import threading
from tkinter import messagebox, ttk
from typing import Callable

from core.vt_client import VirusTotalClient, VTStatus
from gui.i18n import SUPPORTED_LANGUAGES
from core.trust_pipeline import PRIVACY_NOTICE
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
            text=(
                "VirusTotal hesabınızdan ücretsiz bir API anahtarı alıp aşağıya yapıştırın.\n"
                "Anahtar bu bilgisayarda, işletim sisteminin güvenli deposunda (DPAPI) saklanır.\n"
                + PRIVACY_NOTICE + "\n"
                "Çevrimiçi kontrol siz açana kadar kapalıdır."
            ),
            justify="left",
            foreground="#444",
            wraplength=720,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(vt_frame, text="API Anahtarı:").grid(row=1, column=0, sticky="w", pady=(0, 4))
        self.api_key_var = tk.StringVar(value=self._settings.virustotal_api_key)
        self._api_entry = ttk.Entry(
            vt_frame, textvariable=self.api_key_var, show="*", font=("Consolas", 10)
        )
        self._api_entry.grid(row=1, column=1, sticky="ew", padx=(10, 10), pady=(0, 4))

        self._show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            vt_frame, text="Göster", variable=self._show_var, command=self._toggle_visibility
        ).grid(row=1, column=2, sticky="w", pady=(0, 4))

        self.autoquery_var = tk.BooleanVar(value=self._settings.virustotal_autoquery)
        ttk.Checkbutton(
            vt_frame,
            text="Tarama sırasında VirusTotal'a otomatik sor",
            variable=self.autoquery_var,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

        btns = ttk.Frame(vt_frame)
        btns.grid(row=3, column=0, columnspan=3, sticky="e", pady=(12, 0))
        # Leftmost, and deliberately far from the accented "Kaydet": the only
        # destructive control on this screen should not sit under the button
        # the user reaches for by habit.
        self.remove_key_button = ttk.Button(
            btns, text="Anahtarı Kaldır", command=self._on_remove_key
        )
        self.remove_key_button.pack(side="left")
        ttk.Button(btns, text="Anahtarı Test Et", command=self._on_test).pack(
            side="left", padx=(10, 0)
        )
        ttk.Button(btns, text="Kaydet", command=self._on_save, style="Accent.TButton").pack(
            side="left", padx=(10, 0)
        )

        self.test_status_var = tk.StringVar(value="")
        ttk.Label(vt_frame, textvariable=self.test_status_var, foreground="#444").grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )

        # --- History ----------------------------------------------------
        hist_frame = ttk.LabelFrame(self, text="Geçmiş", padding=14)
        hist_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        ttk.Label(hist_frame, text="Geçmişte tutulacak en fazla kayıt sayısı:").grid(
            row=0, column=0, sticky="w"
        )
        self.history_limit_var = tk.IntVar(value=self._settings.history_limit)
        ttk.Spinbox(
            hist_frame, from_=5, to=500, increment=5,
            textvariable=self.history_limit_var, width=8
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

        # --- Language ---------------------------------------------------
        lang_frame = ttk.LabelFrame(self, text="Arayüz Dili", padding=14)
        lang_frame.grid(row=2, column=0, columnspan=3, sticky="ew")
        self.language_var = tk.StringVar(value=self._settings.language)
        for code in SUPPORTED_LANGUAGES:
            label = {"tr": "Türkçe", "en": "English"}.get(code, code)
            ttk.Radiobutton(
                lang_frame, text=label, value=code, variable=self.language_var
            ).pack(side="left", padx=(0, 12))

        ttk.Label(
            lang_frame,
            text="Dil değişikliği “Kaydet” düğmesine bastıktan sonra hemen uygulanır.",
            foreground="#666",
        ).pack(side="left", padx=(10, 0))

    # ------------------------------------------------------------------
    def _toggle_visibility(self) -> None:
        self._api_entry.configure(show="" if self._show_var.get() else "*")

    def _on_save(self) -> None:
        self._settings.virustotal_api_key = self.api_key_var.get().strip()
        self._settings.virustotal_autoquery = bool(self.autoquery_var.get())
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
            messagebox.showerror("Ayarlar kaydedilemedi", str(exc))
            return
        # Only now does the draft become the live configuration.
        self._live_settings = self._settings
        self._on_settings_changed(self._settings)
        self._settings = self._live_settings.copy_for_edit()
        messagebox.showinfo("Ayarlar Kaydedildi", "Ayarlarınız başarıyla kaydedildi.")

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
            "Anahtarı Kaldır",
            "Kayıtlı VirusTotal API anahtarı bu bilgisayardan silinecek.\n\n"
            "Çevrimiçi kontrol, yeni bir anahtar girene kadar çalışmayacak.\n"
            "Devam edilsin mi?",
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
            messagebox.showerror("Anahtar kaldırılamadı", str(exc))
            return

        self._live_settings = self._settings
        self.api_key_var.set("")
        self.test_status_var.set("Kayıtlı anahtar kaldırıldı.")
        self._on_settings_changed(self._settings)
        self._settings = self._live_settings.copy_for_edit()
        messagebox.showinfo(
            "Anahtar Kaldırıldı",
            "Kayıtlı VirusTotal API anahtarı silindi.",
        )

    def _on_test(self) -> None:
        key = self.api_key_var.get().strip()
        if not key:
            self.test_status_var.set("Önce bir API anahtarı girin.")
            return
        self.test_status_var.set("VirusTotal anahtarı test ediliyor…")

        def worker() -> None:
            client = VirusTotalClient(api_key=key, timeout=10.0)
            # Use the canonical empty-string SHA-256 as a known-good hash.
            empty_sha256 = (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            result = client.lookup_hash(empty_sha256)
            self.after(0, lambda: self._on_test_done(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_test_done(self, result) -> None:
        status_messages = {
            VTStatus.OK:            "Anahtar geçerli görünüyor — test sorgusu başarılı.",
            VTStatus.NOT_FOUND:     "Anahtar geçerli (test hash'i veritabanında değil — sorun değil).",
            VTStatus.UNAUTHORIZED:  "Anahtar reddedildi. Anahtarınızı tekrar kontrol edin.",
            VTStatus.RATE_LIMITED:  "Hız limitine takıldınız, biraz sonra deneyin.",
            VTStatus.NETWORK_ERROR: "İnternete ulaşılamadı.",
            VTStatus.NO_API_KEY:    "Bir API anahtarı girin.",
            VTStatus.ERROR:         f"Bilinmeyen hata: {result.message}",
        }
        self.test_status_var.set(status_messages.get(result.status, result.message))
