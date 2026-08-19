"""
Internationalisation (i18n) helper for the GUI.

Keeps the current language as a module-level state so tab widgets can
call `t("some.key")` without having to pass the locale around. The
translation table is a plain dict — simple, zero dependencies, easy to
extend with new locales.
"""

from __future__ import annotations

from typing import Any

SUPPORTED_LANGUAGES: tuple[str, ...] = ("tr", "en")
DEFAULT_LANGUAGE: str = "tr"

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # --- Window / status ------------------------------------------------
        "app.title": "Hash Verification Tool",
        "status.ready": "Ready.",
        "status.error": "Error.",
        "status.busy_title": "Busy",
        "status.busy_body": "Another operation is already running.",
        # Cancellation is cooperative — the worker stops at the next file — so
        # this is what the user sees between the click and the actual stop.
        "status.cancelling": "Cancelling…",
        "status.cancelled": "Cancelled — nothing was written.",

        # --- Menu -----------------------------------------------------------
        "menu.file": "File",
        "menu.exit": "Exit",
        "menu.help": "Help",
        "menu.about": "About",
        "menu.settings": "Settings",
        "menu.language": "Language",
        "menu.language.tr": "Türkçe",
        "menu.language.en": "English",

        # --- About dialog ---------------------------------------------------
        "about.title": "About Hash Verification Tool",
        "about.body": (
            "Hash Verification Tool  v{version}\n\n"
            "Friendly file-trust check: hashes, VirusTotal lookup,\n"
            "digital signature, local fingerprint and a plain-language\n"
            "risk summary — all without uploading the file anywhere.\n\n"
            "Advanced tab still exposes the original hash / verify / report tools.\n"
            "CLI equivalent: main.py hash | verify | report"
        ),

        # --- Notebook tab captions -----------------------------------------
        "tab.trust": "  Trust Check  ",
        "tab.history": "  History  ",
        "tab.settings_tab": "  Settings  ",
        "tab.advanced": "  Advanced  ",
        "tab.hash": "  1. Hash Generate  ",
        "tab.verify": "  2. Verify  ",
        "tab.report": "  3. Report Convert  ",

        # --- Shared ---------------------------------------------------------
        "btn.browse": "Browse…",
        "btn.cancel": "Cancel",

        # --- Hash tab -------------------------------------------------------
        "hash.target": "Target:",
        "hash.mode.file": "Single file",
        "hash.mode.folder": "Folder (recursive)",
        "hash.path": "Path:",
        "hash.algorithm": "Algorithm:",
        "hash.output": "Manifest output (optional):",
        "hash.sign_key": "Signing key (optional):",
        "hash.sign_key.hint": (
            "A private key from keygen. It may not live inside the folder "
            "being scanned or next to the manifest it signs — anyone who "
            "receives those receives the key and can forge manifests. Share "
            "the matching .pub separately."
        ),
        "hash.sign_key.folder_only": (
            "A signing key applies to folder manifests only: a signature "
            "attests to an inventory, and a single-file digest is not one."
        ),
        "hash.btn": "Compute Hash",
        "hash.result": "Result:",
        "hash.picker.file_title": "Select file to hash",
        "hash.picker.folder_title": "Select folder to hash",
        "hash.picker.sign_key_title": "Select signing key",
        "hash.picker.save_title": "Save manifest as…",
        "hash.missing_title": "Missing path",
        "hash.missing_body": "Please select a file or folder.",
        "hash.err_title": "Hash failed",
        "hash.blocked_title": "Cannot run this",
        "hash.no_default_output": (
            "No default manifest name can be derived for {target} ({error}).\n\n"
            "Choose an output file explicitly."
        ),
        "hash.confirm_title": "Are you sure?",
        "hash.confirm_question": "Continue anyway?",
        "hash.status": "Hashing {mode}…",
        "hash.progress": "Hashing  [{done}/{total}]  {path}",
        "hash.log.header": "\n--- Hashing ({mode}, {algo}) ---\n{target}\n",
        "hash.log.digest": "Digest : {digest}\n",
        "hash.log.saved": "Manifest saved: {path}\n",
        "hash.log.signed": "Manifest signed. Verify with the trusted key: {pub}\n",
        "hash.log.count": "Files hashed : {count}\n",
        "hash.log.cancelled": "Cancelled — nothing was written.\n",
        "hash.log.done": "Done.\n",

        # --- Verify tab -----------------------------------------------------
        "verify.folder": "Folder to verify:",
        "verify.manifest": "Manifest JSON:",
        "verify.trusted_key": "Trusted key (optional):",
        "verify.trusted_key.hint": (
            "A .pub file from keygen, or the raw hex. Without one a signature "
            "can only be checked against the manifest's own embedded key, which "
            "shows internal consistency — not who produced it."
        ),
        "verify.trusted_key.tip": (
            "Tip: to establish where this manifest came from, supply the "
            "trusted public key above."
        ),
        "verify.report": "Save report (optional):",
        "verify.btn": "Verify",
        "verify.summary": "Summary:",
        "verify.details": "Details:",
        "verify.col.status": "Status",
        "verify.col.path": "Path",
        "verify.picker.folder_title": "Select folder to verify",
        "verify.picker.manifest_title": "Select manifest JSON",
        "verify.picker.trusted_key_title": "Select trusted public key",
        "verify.picker.report_title": "Save report as…",
        "verify.missing_title": "Missing input",
        "verify.missing_body": "Please select folder and manifest.",
        "verify.err_title": "Verify failed",
        "verify.running": "Verifying…",
        "verify.progress": "Verifying  [{done}/{total}]  {path}",
        "verify.log.folder": "Folder    : {folder}\n",
        "verify.log.algorithm": "Algorithm : {algorithm}\n\n",
        "verify.summary.total_scanned": "Total scanned",
        "verify.summary.unchanged": "Unchanged",
        "verify.summary.modified": "Modified",
        "verify.summary.new": "New",
        "verify.summary.missing": "Missing",
        "verify.summary.errors": "Errors",
        "verify.result.clean": "Integrity OK.",
        "verify.result.dirty": "Differences detected.",
        "verify.log.report_saved": "Report saved: {path}\n",

        # --- Report tab -----------------------------------------------------
        "report.input": "Input JSON report:",
        "report.format": "Output format:",
        "report.output": "Output path (optional):",
        "report.btn": "Convert",
        "report.log": "Log:",
        "report.picker.input_title": "Select JSON report",
        "report.picker.output_title": "Save converted report as…",
        "report.missing_title": "Missing input",
        "report.missing_body": "Please select an input report.",
        "report.err_title": "Convert failed",
        "report.running": "Converting report…",
        "report.log.start": "Converting {inp} -> {fmt}\n",
        "report.log.done": "Done: {path}\n",

        # ====================================================================
        # The three default screens: Trust Check, History, Settings.
        #
        # These carried no keys at all. Choosing English translated the menu,
        # the tab captions and the Advanced tabs, and left everything under
        # them in Turkish — so the menu described a language the application
        # did not actually offer.
        # ====================================================================

        # --- Shared across the three screens --------------------------------
        "btn.copy": "Copy",
        "kv.status": "Status",
        "kv.detail": "Explanation",

        # The Turkish value of this key must stay identical to
        # core.trust_pipeline.PRIVACY_NOTICE — one statement about what leaves
        # the machine, held in place by a test.
        "privacy.notice": (
            "Your file is not uploaded. Only its SHA-256 digest is sent to "
            "VirusTotal; that request can be linked to your IP address and "
            "API account."
        ),

        # --- Risk vocabulary ------------------------------------------------
        # Two registers on purpose: the badge is a verdict, the history column
        # is a field in a table and has no room to repeat the word "risk".
        "risk.badge.low": "Low Risk",
        "risk.badge.medium": "Medium Risk",
        "risk.badge.high": "High Risk",
        "risk.badge.unknown": "Unknown",
        "risk.level.low": "Low",
        "risk.level.medium": "Medium",
        "risk.level.high": "High",
        "risk.level.unknown": "Unknown",

        # --- Trust Check: layout --------------------------------------------
        "trust.section.pick": "1. Choose a File",
        "trust.section.summary": "2. Result Summary",
        "trust.section.fingerprint": "3. File Fingerprint (SHA-256)",
        "trust.no_file": (
            "No file selected yet. Use the button on the right, or drag a "
            "file onto the window."
        ),
        "trust.selected": "Selected file: {name}\n{path}",
        "trust.btn.pick": "Choose File…",
        "trust.btn.scan": "Start Scan",
        "trust.btn.rescan": "Scan Again",
        "trust.btn.remember": "Remember Fingerprint",
        "trust.btn.export_json": "Save Report (JSON)",
        "trust.btn.export_html": "Save Report (HTML)",
        "trust.online.on": "Online check: On",
        "trust.online.off": "Online check: Off",
        "trust.summary.idle": (
            "Pick a file and press “Start Scan” — the result will appear here."
        ),
        "trust.fingerprint.hint": (
            "This code is the file's unique fingerprint. Same code = same "
            "file. A different code means the file has changed."
        ),
        "trust.details.title": "Technical Details",
        "trust.details.show": "Show ▾",
        "trust.details.hide": "Hide ▴",
        "trust.tab.file": "File Details",
        "trust.tab.hashes": "Hashes (MD5 / SHA-1)",
        "trust.tab.vt": "VirusTotal",
        "trust.tab.signature": "Digital Signature",
        "trust.tab.local": "Local Record",
        "trust.hashes.legacy_warning": (
            "MD5 and SHA-1 are older hash algorithms and are considered "
            "cryptographically broken. They are shown here only for "
            "compatibility with older software. The real fingerprint is the "
            "SHA-256 above."
        ),

        # --- Trust Check: file selection ------------------------------------
        "trust.picker.file_title": "Select the file to check",
        "trust.invalid.title": "Invalid File",
        "trust.invalid.body": "This path does not point to a file:\n{path}",
        "trust.missing_from_history": (
            "No file selected — the file in that record could not be found."
        ),

        # --- Trust Check: scan states ---------------------------------------
        "trust.badge.scanning": "Scanning…",
        "trust.summary.scanning": "Scanning the file, please wait…",
        "trust.status.starting": "Starting scan — {name}",
        "trust.status.done": "Done.",
        "trust.status.failed": "The scan could not be completed.",
        "trust.status.cancelled": "Cancelled.",
        "trust.kv.not_scanned": "Not scanned yet",
        "trust.error.headline": "The scan could not be completed",
        "trust.error.detail": (
            "The file could not be read, or the check could not finish: {error}"
        ),
        "trust.error.title": "Scan Error",
        "trust.failure.advice": "Fix the problem and try again.",
        "trust.cancelled.headline": "Scan cancelled",
        "trust.cancelled.detail": "You cancelled the scan, so it did not finish.",
        "trust.cancelled.advice": "You can scan again whenever you are ready.",
        "trust.copied": "Hash copied to the clipboard ({count} characters).",
        "trust.history_fail.title": "Could not be saved to History",
        "trust.history_fail.body": (
            "The scan finished but could not be written to the history:\n{error}"
        ),

        # --- Trust Check: file details --------------------------------------
        "trust.file.name": "File Name",
        "trust.file.path": "Full Path",
        "trust.file.size": "Size",
        "trust.file.size_value": "{human}  ({size} bytes)",
        "trust.file.extension": "Extension",
        "trust.file.created": "Created",
        "trust.file.modified": "Last Modified",

        # --- Trust Check: VirusTotal ----------------------------------------
        "trust.vt.not_queried": "Not queried (turned off)",
        "trust.vt.no_key": "No API key configured",
        "trust.vt.no_key_hint_label": "Note",
        "trust.vt.no_key_hint": (
            "You can enter your VirusTotal API key on the Settings tab."
        ),
        "trust.vt.ok": "Query succeeded",
        "trust.vt.malicious": "Malicious",
        "trust.vt.suspicious": "Suspicious",
        "trust.vt.harmless": "Harmless",
        "trust.vt.undetected": "Undetected",
        "trust.vt.total_engines": "Engines total",
        "trust.vt.last_analysis": "Last analysis",
        "trust.vt.reputation": "Reputation",
        "trust.vt.type_description": "File type guess",
        "trust.vt.meaningful_name": "Known name",

        # --- Trust Check: signature -----------------------------------------
        "trust.sig.not_checked": "Not checked",
        "trust.sig.signer": "Signed by",
        "trust.sig.raw_status": "Raw status",
        "trust.sig.signed_valid": "Signed (valid)",
        "trust.sig.hash_mismatch": "Signed, but the contents changed (hash mismatch)",
        "trust.sig.untrusted": "Signed, but the certificate is not trusted",
        "trust.sig.unsigned": "Not signed",
        "trust.sig.not_applicable": "Does not apply to this file type",
        "trust.sig.unknown": "Inconclusive",
        "trust.sig.unsupported": "Not supported (Windows only)",
        "trust.sig.error": "Error",

        # --- Trust Check: local record --------------------------------------
        "trust.local.not_compared": "No local comparison was made",
        "trust.local.same": "Same file",
        "trust.local.changed": "The file has changed!",
        "trust.local.new": "New record created",
        "trust.local.not_tracked": "No record found",
        "trust.local.previous_hash": "Previous SHA-256",
        "trust.local.current_hash": "Current SHA-256",
        "trust.local.first_seen": "First recorded",
        "trust.local.last_seen": "Last updated",

        # --- Trust Check: remember (baseline) -------------------------------
        "trust.remember.blocked_title": "Cannot be saved",
        "trust.remember.current_title": "Already up to date",
        "trust.remember.replace_title": "Replace the baseline",
        "trust.remember.risky_title": "Save it anyway?",
        "trust.remember.failed_title": "Could not be saved",
        "trust.remember.reread_failed": "The file could not be read again: {error}",
        "trust.remember.changed_after_scan": (
            "The file changed after the scan finished, so this version was not "
            "recorded as the baseline. Please scan it again."
        ),
        "trust.remember.done_title": "Fingerprint saved",
        "trust.remember.done_body": (
            "The local record has been updated. Next time you scan this file "
            "you will be told whether it changed."
        ),

        # --- Trust Check: export --------------------------------------------
        "trust.export.title": "Save Report",
        "trust.export.filename": "{stem}_trust_report",
        "trust.export.all_files": "All files",
        "trust.export.error_title": "Report Error",
        "trust.export.done_title": "Report Saved",
        "trust.export.done_body": "The report was written to:\n{path}",

        # --- History --------------------------------------------------------
        "history.header": (
            "Recently scanned files (newest first). Double-click a row to "
            "scan it again."
        ),
        "history.btn.refresh": "Refresh",
        "history.btn.clear": "Clear History",
        "history.empty": "Nothing has been scanned yet.",
        "history.col.scanned_at": "Date",
        "history.col.file_name": "File",
        "history.col.risk": "Risk",
        "history.col.vt": "VirusTotal",
        "history.col.signature": "Signature",
        "history.col.path": "Path",
        "history.clear.title": "Clear History",
        "history.clear.question": (
            "Are you sure you want to delete the entire scan history?"
        ),
        "history.clear.failed_title": "History could not be cleared",
        "history.sig.signed_valid": "Signed (valid)",
        "history.sig.signed_invalid": "Signed (invalid)",
        "history.sig.unsigned": "Not signed",
        "history.sig.error": "Error",
        "history.sig.unknown": "Inconclusive",
        "history.vt.clean": "No flags",
        "history.vt.malicious": "{count} malicious",
        "history.vt.suspicious": "{count} suspicious",
        "history.vt.not_found": "Not found",
        "history.vt.no_key": "No key",
        "history.vt.unavailable": "Could not be queried",

        # --- Settings -------------------------------------------------------
        "settings.vt.intro": (
            "Get a free API key from your VirusTotal account and paste it below.\n"
            "The key is kept on this computer, in the operating system's secure "
            "store (DPAPI).\n"
            "{privacy}\n"
            "Online checking stays off until you turn it on."
        ),
        "settings.vt.api_key": "API Key:",
        "settings.vt.show": "Show",
        "settings.vt.autoquery": "Ask VirusTotal automatically while scanning",
        "settings.vt.remove": "Remove Key",
        "settings.vt.test": "Test Key",
        "settings.btn.save": "Save",
        "settings.history.title": "History",
        "settings.history.limit": "Maximum number of records to keep:",
        "settings.language.title": "Interface Language",
        "settings.language.hint": (
            "The language change takes effect as soon as you press “Save”."
        ),
        "settings.language.save_failed_title": "Settings",
        "settings.language.save_failed_body": (
            "The language preference could not be saved: {error}"
        ),
        "settings.save.failed_title": "Settings could not be saved",
        "settings.save.done_title": "Settings Saved",
        "settings.save.done_body": "Your settings were saved successfully.",
        "settings.remove.title": "Remove Key",
        "settings.remove.question": (
            "The stored VirusTotal API key will be deleted from this computer.\n\n"
            "Online checking will not work until you enter a new key.\n"
            "Continue?"
        ),
        "settings.remove.failed_title": "The key could not be removed",
        "settings.remove.status": "The stored key was removed.",
        "settings.remove.done_title": "Key Removed",
        "settings.remove.done_body": "The stored VirusTotal API key was deleted.",
        "settings.test.no_key": "Enter an API key first.",
        "settings.test.running": "Testing the VirusTotal key…",
        "settings.test.ok": "The key looks valid — the test query succeeded.",
        "settings.test.not_found": (
            "The key is valid (the test hash is not in the database — that is fine)."
        ),
        "settings.test.unauthorized": "The key was rejected. Check your key again.",
        "settings.test.rate_limited": "You hit the rate limit; try again shortly.",
        "settings.test.network_error": "The internet could not be reached.",
        "settings.test.missing": "Enter an API key.",
        "settings.test.error": "Unknown error: {error}",
    },
    "tr": {
        # --- Pencere / durum ------------------------------------------------
        "app.title": "Hash Doğrulama Aracı",
        "status.ready": "Hazır.",
        "status.error": "Hata.",
        "status.busy_title": "Meşgul",
        "status.busy_body": "Başka bir işlem şu anda çalışıyor.",
        "status.cancelling": "İptal ediliyor…",
        "status.cancelled": "İptal edildi — hiçbir şey yazılmadı.",

        # --- Menü -----------------------------------------------------------
        "menu.file": "Dosya",
        "menu.exit": "Çıkış",
        "menu.help": "Yardım",
        "menu.about": "Hakkında",
        "menu.settings": "Ayarlar",
        "menu.language": "Dil",
        "menu.language.tr": "Türkçe",
        "menu.language.en": "English",

        # --- Hakkında -------------------------------------------------------
        "about.title": "Hash Doğrulama Aracı Hakkında",
        "about.body": (
            "Hash Doğrulama Aracı  v{version}\n\n"
            "Acemi dostu dosya güven kontrolü: hash, VirusTotal hash lookup,\n"
            "dijital imza, yerel parmak izi karşılaştırması ve sade Türkçe\n"
            "risk özeti. Dosya hiçbir yere yüklenmez.\n\n"
            "Gelişmiş sekmesi orijinal hash / doğrula / rapor araçlarını\n"
            "olduğu gibi içerir.\n"
            "Komut satırı karşılığı: main.py hash | verify | report"
        ),

        # --- Sekme başlıkları ----------------------------------------------
        "tab.trust": "  Güven Kontrolü  ",
        "tab.history": "  Geçmiş  ",
        "tab.settings_tab": "  Ayarlar  ",
        "tab.advanced": "  Gelişmiş  ",
        "tab.hash": "  1. Hash Üret  ",
        "tab.verify": "  2. Doğrula  ",
        "tab.report": "  3. Rapor Dönüştür  ",

        # --- Ortak ----------------------------------------------------------
        "btn.browse": "Gözat…",
        "btn.cancel": "İptal",

        # --- Hash sekmesi ---------------------------------------------------
        "hash.target": "Hedef:",
        "hash.mode.file": "Tek dosya",
        "hash.mode.folder": "Klasör (alt klasörler dâhil)",
        "hash.path": "Yol:",
        "hash.algorithm": "Algoritma:",
        "hash.output": "Manifest çıktısı (opsiyonel):",
        "hash.sign_key": "İmzalama anahtarı (opsiyonel):",
        "hash.sign_key.hint": (
            "keygen'in ürettiği özel anahtar. Taranan klasörün içinde ya da "
            "imzaladığı manifestin yanında olamaz — onları alan herkes anahtarı "
            "da alır ve sizin adınıza manifest imzalayabilir. Eşleşen .pub "
            "dosyasını ayrı bir kanalla iletin."
        ),
        "hash.sign_key.folder_only": (
            "İmzalama anahtarı yalnız klasör manifestleri için geçerli: imza bir "
            "envantere tanıklık eder, tek dosyanın özeti envanter değildir."
        ),
        "hash.btn": "Hash Hesapla",
        "hash.result": "Sonuç:",
        "hash.picker.file_title": "Hash'lenecek dosyayı seç",
        "hash.picker.folder_title": "Hash'lenecek klasörü seç",
        "hash.picker.sign_key_title": "İmzalama anahtarını seç",
        "hash.picker.save_title": "Manifest'i farklı kaydet…",
        "hash.missing_title": "Yol eksik",
        "hash.missing_body": "Lütfen bir dosya veya klasör seçin.",
        "hash.err_title": "Hash başarısız",
        "hash.blocked_title": "Bu işlem yapılamaz",
        "hash.no_default_output": (
            "{target} için varsayılan bir manifest adı türetilemiyor ({error}).\n\n"
            "Kaydetme hedefini elle seçin."
        ),
        "hash.confirm_title": "Emin misiniz?",
        "hash.confirm_question": "Yine de devam edilsin mi?",
        "hash.status": "Hash hesaplanıyor ({mode})…",
        "hash.progress": "Hash'leniyor  [{done}/{total}]  {path}",
        "hash.log.header": "\n--- Hash ({mode}, {algo}) ---\n{target}\n",
        "hash.log.digest": "Özet    : {digest}\n",
        "hash.log.saved": "Manifest kaydedildi: {path}\n",
        "hash.log.signed": "Manifest imzalandı. Doğrularken güvenilen anahtar: {pub}\n",
        "hash.log.count": "Hash'lenen dosya : {count}\n",
        "hash.log.cancelled": "İptal edildi — hiçbir şey yazılmadı.\n",
        "hash.log.done": "Tamamlandı.\n",

        # --- Doğrula sekmesi -----------------------------------------------
        "verify.folder": "Doğrulanacak klasör:",
        "verify.manifest": "Manifest JSON:",
        "verify.trusted_key": "Güvenilen anahtar (opsiyonel):",
        "verify.trusted_key.hint": (
            "keygen'in ürettiği .pub dosyası ya da ham hex. Bu olmadan imza "
            "yalnızca manifestin kendi gömülü anahtarıyla doğrulanabilir; bu da "
            "içeriğin kendi içinde tutarlı olduğunu gösterir — kimin ürettiğini "
            "değil."
        ),
        "verify.trusted_key.tip": (
            "İpucu: bu manifestin kaynağını doğrulamak için yukarıya güvendiğiniz "
            "genel anahtarı verin."
        ),
        "verify.report": "Raporu kaydet (opsiyonel):",
        "verify.btn": "Doğrula",
        "verify.summary": "Özet:",
        "verify.details": "Ayrıntılar:",
        "verify.col.status": "Durum",
        "verify.col.path": "Yol",
        "verify.picker.folder_title": "Doğrulanacak klasörü seç",
        "verify.picker.manifest_title": "Manifest JSON seç",
        "verify.picker.trusted_key_title": "Güvenilen genel anahtarı seç",
        "verify.picker.report_title": "Raporu farklı kaydet…",
        "verify.missing_title": "Girdi eksik",
        "verify.missing_body": "Lütfen klasör ve manifest seçin.",
        "verify.err_title": "Doğrulama başarısız",
        "verify.running": "Doğrulanıyor…",
        "verify.progress": "Doğrulanıyor  [{done}/{total}]  {path}",
        "verify.log.folder": "Klasör    : {folder}\n",
        "verify.log.algorithm": "Algoritma : {algorithm}\n\n",
        "verify.summary.total_scanned": "Toplam taranan",
        "verify.summary.unchanged": "Değişmemiş",
        "verify.summary.modified": "Değişmiş",
        "verify.summary.new": "Yeni",
        "verify.summary.missing": "Eksik",
        "verify.summary.errors": "Hatalar",
        "verify.result.clean": "Bütünlük sağlandı.",
        "verify.result.dirty": "Farklılıklar bulundu.",
        "verify.log.report_saved": "Rapor kaydedildi: {path}\n",

        # --- Rapor Dönüştür sekmesi ----------------------------------------
        "report.input": "Girdi JSON rapor:",
        "report.format": "Çıktı formatı:",
        "report.output": "Çıktı yolu (opsiyonel):",
        "report.btn": "Dönüştür",
        "report.log": "Günlük:",
        "report.picker.input_title": "JSON rapor seç",
        "report.picker.output_title": "Dönüştürülen raporu farklı kaydet…",
        "report.missing_title": "Girdi eksik",
        "report.missing_body": "Lütfen bir girdi raporu seçin.",
        "report.err_title": "Dönüştürme başarısız",
        "report.running": "Rapor dönüştürülüyor…",
        "report.log.start": "Dönüştürülüyor: {inp} -> {fmt}\n",
        "report.log.done": "Tamamlandı: {path}\n",

        # ====================================================================
        # Üç varsayılan ekran: Güven Kontrolü, Geçmiş, Ayarlar.
        #
        # Değerler bu ekranlarda hâlihazırda yazan metinlerin aynısıdır: bu
        # tur çeviriyi mümkün kılıyor, Türkçe arayüzü değiştirmiyor.
        # ====================================================================

        # --- Üç ekranda ortak ------------------------------------------------
        "btn.copy": "Kopyala",
        "kv.status": "Durum",
        "kv.detail": "Açıklama",

        # core.trust_pipeline.PRIVACY_NOTICE ile birebir aynı kalmalı — makineden
        # ne çıktığına dair tek bir cümle, testle yerinde tutuluyor.
        "privacy.notice": (
            "Dosyanız yüklenmez. Yalnızca dosyanın SHA-256 özeti VirusTotal'a "
            "gönderilir; bu istek IP adresiniz ve API hesabınızla ilişkilendirilebilir."
        ),

        # --- Risk sözlüğü -----------------------------------------------------
        "risk.badge.low": "Düşük Risk",
        "risk.badge.medium": "Orta Risk",
        "risk.badge.high": "Yüksek Risk",
        "risk.badge.unknown": "Bilinmiyor",
        "risk.level.low": "Düşük",
        "risk.level.medium": "Orta",
        "risk.level.high": "Yüksek",
        "risk.level.unknown": "Bilinmiyor",

        # --- Güven Kontrolü: yerleşim ----------------------------------------
        "trust.section.pick": "1. Dosya Seçin",
        "trust.section.summary": "2. Sonuç Özeti",
        "trust.section.fingerprint": "3. Dosya Parmak İzi (SHA-256)",
        "trust.no_file": (
            "Henüz dosya seçilmedi. Sağdaki düğmeyi kullanın veya dosyayı "
            "pencereye sürükleyin."
        ),
        "trust.selected": "Seçili dosya: {name}\n{path}",
        "trust.btn.pick": "Dosya Seç…",
        "trust.btn.scan": "Taramayı Başlat",
        "trust.btn.rescan": "Tekrar Tara",
        "trust.btn.remember": "Parmak İzini Kaydet",
        "trust.btn.export_json": "Raporu Kaydet (JSON)",
        "trust.btn.export_html": "Raporu Kaydet (HTML)",
        "trust.online.on": "Çevrimiçi kontrol: Açık",
        "trust.online.off": "Çevrimiçi kontrol: Kapalı",
        "trust.summary.idle": (
            "Bir dosya seçip “Taramayı Başlat” düğmesine bastığınızda sonuç "
            "burada görünecek."
        ),
        "trust.fingerprint.hint": (
            "Bu kod dosyanın benzersiz parmak izidir. Aynı kod = aynı dosya. "
            "Farklı kod = dosya değişmiş demektir."
        ),
        "trust.details.title": "Teknik Detaylar",
        "trust.details.show": "Göster ▾",
        "trust.details.hide": "Gizle ▴",
        "trust.tab.file": "Dosya Bilgileri",
        "trust.tab.hashes": "Hash (MD5 / SHA-1)",
        "trust.tab.vt": "VirusTotal",
        "trust.tab.signature": "Dijital İmza",
        "trust.tab.local": "Yerel Kayıt",
        "trust.hashes.legacy_warning": (
            "MD5 ve SHA-1 eski hash algoritmalarıdır ve kriptografik açıdan "
            "kırılmış sayılırlar. Yalnızca eski yazılımlarla uyumluluk için "
            "burada gösteriliyorlar. Asıl parmak izi yukarıdaki SHA-256'dır."
        ),

        # --- Güven Kontrolü: dosya seçimi ------------------------------------
        "trust.picker.file_title": "Kontrol Edilecek Dosyayı Seçin",
        "trust.invalid.title": "Geçersiz Dosya",
        "trust.invalid.body": "Bu yol bir dosyaya işaret etmiyor:\n{path}",
        "trust.missing_from_history": "Seçili dosya yok — kayıttaki dosya bulunamadı.",

        # --- Güven Kontrolü: tarama durumları --------------------------------
        "trust.badge.scanning": "Taranıyor…",
        "trust.summary.scanning": "Dosya taranıyor, lütfen bekleyin…",
        "trust.status.starting": "Tarama başlatılıyor — {name}",
        "trust.status.done": "Tamamlandı.",
        "trust.status.failed": "Tarama tamamlanamadı.",
        "trust.status.cancelled": "İptal edildi.",
        "trust.kv.not_scanned": "Henüz tarama yapılmadı",
        "trust.error.headline": "Tarama tamamlanamadı",
        "trust.error.detail": "Dosya okunamadı veya kontrol tamamlanamadı: {error}",
        "trust.error.title": "Tarama Hatası",
        "trust.failure.advice": "Sorunu giderip tekrar deneyin.",
        "trust.cancelled.headline": "Tarama iptal edildi",
        "trust.cancelled.detail": "Tarama siz iptal ettiğiniz için tamamlanmadı.",
        "trust.cancelled.advice": "Hazır olduğunuzda yeniden tarayabilirsiniz.",
        "trust.copied": "Hash panoya kopyalandı ({count} karakter).",
        "trust.history_fail.title": "Geçmişe kaydedilemedi",
        "trust.history_fail.body": (
            "Tarama tamamlandı ancak geçmişe yazılamadı:\n{error}"
        ),

        # --- Güven Kontrolü: dosya bilgileri ---------------------------------
        "trust.file.name": "Dosya Adı",
        "trust.file.path": "Tam Yol",
        "trust.file.size": "Boyut",
        "trust.file.size_value": "{human}  ({size} bayt)",
        "trust.file.extension": "Uzantı",
        "trust.file.created": "Oluşturulma",
        "trust.file.modified": "Son Değişiklik",

        # --- Güven Kontrolü: VirusTotal --------------------------------------
        "trust.vt.not_queried": "Sorgu yapılmadı (kapalı)",
        "trust.vt.no_key": "API anahtarı ayarlanmamış",
        "trust.vt.no_key_hint_label": "Bilgi",
        "trust.vt.no_key_hint": (
            "Ayarlar sekmesinden VirusTotal API anahtarınızı girebilirsiniz."
        ),
        "trust.vt.ok": "Sorgu başarılı",
        "trust.vt.malicious": "Zararlı (malicious)",
        "trust.vt.suspicious": "Şüpheli (suspicious)",
        "trust.vt.harmless": "Temiz (harmless)",
        "trust.vt.undetected": "Algılanmadı (undetected)",
        "trust.vt.total_engines": "Toplam motor",
        "trust.vt.last_analysis": "Son analiz",
        "trust.vt.reputation": "İtibar (reputation)",
        "trust.vt.type_description": "Dosya türü tahmini",
        "trust.vt.meaningful_name": "Bilinen isim",

        # --- Güven Kontrolü: imza --------------------------------------------
        "trust.sig.not_checked": "Kontrol yapılmadı",
        "trust.sig.signer": "İmzalayan",
        "trust.sig.raw_status": "Ham durum",
        "trust.sig.signed_valid": "İmzalı (geçerli)",
        "trust.sig.hash_mismatch": "İmzalı ama içerik değişmiş (hash uyuşmuyor)",
        "trust.sig.untrusted": "İmzalı ama sertifika güvenilmez",
        "trust.sig.unsigned": "İmza yok",
        "trust.sig.not_applicable": "Bu dosya türüne uygulanamaz",
        "trust.sig.unknown": "Belirsiz",
        "trust.sig.unsupported": "Desteklenmiyor (yalnızca Windows)",
        "trust.sig.error": "Hata",

        # --- Güven Kontrolü: yerel kayıt -------------------------------------
        "trust.local.not_compared": "Yerel karşılaştırma yapılmadı",
        "trust.local.same": "Aynı dosya",
        "trust.local.changed": "Değişmiş dosya!",
        "trust.local.new": "Yeni kayıt oluşturuldu",
        "trust.local.not_tracked": "Kayıt bulunamadı",
        "trust.local.previous_hash": "Önceki SHA-256",
        "trust.local.current_hash": "Şimdiki SHA-256",
        "trust.local.first_seen": "İlk kayıt",
        "trust.local.last_seen": "Son güncelleme",

        # --- Güven Kontrolü: parmak izini kaydetme ---------------------------
        "trust.remember.blocked_title": "Kaydedilemez",
        "trust.remember.current_title": "Zaten güncel",
        "trust.remember.replace_title": "Temel sürümü değiştir",
        "trust.remember.risky_title": "Yine de kaydedilsin mi?",
        "trust.remember.failed_title": "Kaydedilemedi",
        "trust.remember.reread_failed": "Dosya yeniden okunamadı: {error}",
        "trust.remember.changed_after_scan": (
            "Dosya tarama tamamlandıktan sonra değişti; bu sürüm temel sürüm "
            "olarak kaydedilmedi. Lütfen yeniden tarayın."
        ),
        "trust.remember.done_title": "Parmak izi kaydedildi",
        "trust.remember.done_body": (
            "Yerel kayıt güncellendi. Bu dosyayı ileride taradığınızda değişip "
            "değişmediği gösterilecek."
        ),

        # --- Güven Kontrolü: rapor dışa aktarma ------------------------------
        "trust.export.title": "Raporu Kaydet",
        "trust.export.filename": "{stem}_guven_raporu",
        "trust.export.all_files": "Tüm dosyalar",
        "trust.export.error_title": "Rapor Hatası",
        "trust.export.done_title": "Rapor Kaydedildi",
        "trust.export.done_body": "Rapor şu dosyaya yazıldı:\n{path}",

        # --- Geçmiş -----------------------------------------------------------
        "history.header": (
            "Son taranan dosyalar (yeniden eskiye). Yeniden taramak için "
            "satıra çift tıklayın."
        ),
        "history.btn.refresh": "Yenile",
        "history.btn.clear": "Geçmişi Temizle",
        "history.empty": "Henüz tarama yapılmadı.",
        "history.col.scanned_at": "Tarih",
        "history.col.file_name": "Dosya",
        "history.col.risk": "Risk",
        "history.col.vt": "VirusTotal",
        "history.col.signature": "İmza",
        "history.col.path": "Yol",
        "history.clear.title": "Geçmişi Temizle",
        "history.clear.question": (
            "Tüm tarama geçmişini silmek istediğinize emin misiniz?"
        ),
        "history.clear.failed_title": "Geçmiş temizlenemedi",
        "history.sig.signed_valid": "İmzalı (geçerli)",
        "history.sig.signed_invalid": "İmzalı (geçersiz)",
        "history.sig.unsigned": "İmza yok",
        "history.sig.error": "Hata",
        "history.sig.unknown": "Belirsiz",
        "history.vt.clean": "Temiz işaret yok",
        "history.vt.malicious": "{count} zararlı",
        "history.vt.suspicious": "{count} şüpheli",
        "history.vt.not_found": "Bulunamadı",
        "history.vt.no_key": "Anahtar yok",
        "history.vt.unavailable": "Sorgulanamadı",

        # --- Ayarlar ----------------------------------------------------------
        "settings.vt.intro": (
            "VirusTotal hesabınızdan ücretsiz bir API anahtarı alıp aşağıya yapıştırın.\n"
            "Anahtar bu bilgisayarda, işletim sisteminin güvenli deposunda (DPAPI) saklanır.\n"
            "{privacy}\n"
            "Çevrimiçi kontrol siz açana kadar kapalıdır."
        ),
        "settings.vt.api_key": "API Anahtarı:",
        "settings.vt.show": "Göster",
        "settings.vt.autoquery": "Tarama sırasında VirusTotal'a otomatik sor",
        "settings.vt.remove": "Anahtarı Kaldır",
        "settings.vt.test": "Anahtarı Test Et",
        "settings.btn.save": "Kaydet",
        "settings.history.title": "Geçmiş",
        "settings.history.limit": "Geçmişte tutulacak en fazla kayıt sayısı:",
        "settings.language.title": "Arayüz Dili",
        "settings.language.hint": (
            "Dil değişikliği “Kaydet” düğmesine bastıktan sonra hemen uygulanır."
        ),
        "settings.language.save_failed_title": "Ayarlar",
        "settings.language.save_failed_body": "Dil tercihi kaydedilemedi: {error}",
        "settings.save.failed_title": "Ayarlar kaydedilemedi",
        "settings.save.done_title": "Ayarlar Kaydedildi",
        "settings.save.done_body": "Ayarlarınız başarıyla kaydedildi.",
        "settings.remove.title": "Anahtarı Kaldır",
        "settings.remove.question": (
            "Kayıtlı VirusTotal API anahtarı bu bilgisayardan silinecek.\n\n"
            "Çevrimiçi kontrol, yeni bir anahtar girene kadar çalışmayacak.\n"
            "Devam edilsin mi?"
        ),
        "settings.remove.failed_title": "Anahtar kaldırılamadı",
        "settings.remove.status": "Kayıtlı anahtar kaldırıldı.",
        "settings.remove.done_title": "Anahtar Kaldırıldı",
        "settings.remove.done_body": "Kayıtlı VirusTotal API anahtarı silindi.",
        "settings.test.no_key": "Önce bir API anahtarı girin.",
        "settings.test.running": "VirusTotal anahtarı test ediliyor…",
        "settings.test.ok": "Anahtar geçerli görünüyor — test sorgusu başarılı.",
        "settings.test.not_found": (
            "Anahtar geçerli (test hash'i veritabanında değil — sorun değil)."
        ),
        "settings.test.unauthorized": "Anahtar reddedildi. Anahtarınızı tekrar kontrol edin.",
        "settings.test.rate_limited": "Hız limitine takıldınız, biraz sonra deneyin.",
        "settings.test.network_error": "İnternete ulaşılamadı.",
        "settings.test.missing": "Bir API anahtarı girin.",
        "settings.test.error": "Bilinmeyen hata: {error}",
    },
}


_current_language: str = DEFAULT_LANGUAGE


def get_language() -> str:
    """Return the currently-active language code."""
    return _current_language


def set_language(lang: str) -> None:
    """Set the active language (silently ignored if unsupported)."""
    global _current_language
    if lang in SUPPORTED_LANGUAGES:
        _current_language = lang


def t(key: str, **kwargs: Any) -> str:
    """
    Look up *key* in the active language table.

    Falls back to English if the key is missing in the current locale,
    then to the raw key string if it is missing everywhere. Values may
    contain ``str.format`` placeholders, which are substituted using
    the keyword arguments.
    """
    table = _TRANSLATIONS.get(_current_language, {})
    text = table.get(key) or _TRANSLATIONS["en"].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return text
