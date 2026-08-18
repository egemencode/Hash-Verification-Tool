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
        "hash.btn": "Compute Hash",
        "hash.result": "Result:",
        "hash.picker.file_title": "Select file to hash",
        "hash.picker.folder_title": "Select folder to hash",
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
        "hash.log.count": "Files hashed : {count}\n",
        "hash.log.cancelled": "Cancelled — nothing was written.\n",
        "hash.log.done": "Done.\n",

        # --- Verify tab -----------------------------------------------------
        "verify.folder": "Folder to verify:",
        "verify.manifest": "Manifest JSON:",
        "verify.trusted_key": "Trusted key (optional):",
        "verify.trusted_key.hint": (
            "A .pub file from `keygen`, or the raw hex. Without one a signature "
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
        "hash.btn": "Hash Hesapla",
        "hash.result": "Sonuç:",
        "hash.picker.file_title": "Hash'lenecek dosyayı seç",
        "hash.picker.folder_title": "Hash'lenecek klasörü seç",
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
        "hash.log.count": "Hash'lenen dosya : {count}\n",
        "hash.log.cancelled": "İptal edildi — hiçbir şey yazılmadı.\n",
        "hash.log.done": "Tamamlandı.\n",

        # --- Doğrula sekmesi -----------------------------------------------
        "verify.folder": "Doğrulanacak klasör:",
        "verify.manifest": "Manifest JSON:",
        "verify.trusted_key": "Güvenilen anahtar (opsiyonel):",
        "verify.trusted_key.hint": (
            "`keygen`'in ürettiği .pub dosyası ya da ham hex. Bu olmadan imza "
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
