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
        "menu.tools": "Tools",
        "footer.studio": "torpilstudio.com",
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
            "Choose a file, or drop it on this window — it is scanned right "
            "away and the verdict appears here."
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

        # ====================================================================
        # The verdict itself.
        #
        # core/risk_engine.py and core/smart_summary.py decide which of these
        # is true and hand back a key; nothing in core reads this table. The
        # wording carries a rule the code cannot enforce: none of it says a
        # file is safe. No tool can establish that, and a translation that
        # quietly promises it would be a worse defect than an untranslated one.
        # ====================================================================

        # --- Headline above the risk badge ----------------------------------
        "risk.headline.low": "No strong sign of risk was found.",
        "risk.headline.medium": "Take care — there are some suspicious signs.",
        "risk.headline.high": "This file may be dangerous.",
        "risk.headline.unknown": "There is not enough data about this file.",

        # --- Advice line ----------------------------------------------------
        "summary.advice.low": (
            "That does not mean the file is definitely safe — only open files "
            "you downloaded from sources you trust."
        ),
        "summary.advice.medium": (
            "Check where the file came from, and the address you downloaded it "
            "from, before you open it."
        ),
        "summary.advice.high": (
            "We recommend not running this file. If it looks suspicious, delete "
            "it, and do not use it again without re-examining where it came from."
        ),
        "summary.advice.unknown": (
            "For a clearer result you can add your VirusTotal API key in "
            "Settings, or remember the file so you are told later whether it "
            "has changed."
        ),

        # --- Summary bullets: VirusTotal ------------------------------------
        "summary.vt.no_usable_analysis": (
            "A VirusTotal result came back, but no usable engine analysis was "
            "in it; this cannot count as a sign of safety."
        ),
        "summary.vt.clean_but_stale": (
            "VirusTotal shows no malicious flag, but that result is very old; "
            "it is not current evidence about the file as it is now."
        ),
        "summary.vt.clean_but_undated": (
            "VirusTotal shows no malicious flag, but that result cannot be "
            "dated; it is not current evidence about the file as it is now."
        ),
        "summary.vt.clean": (
            "No security engine on VirusTotal flagged this as malicious or "
            "suspicious."
        ),
        "summary.vt.suspicious_only": (
            "{count} engines found this file suspicious, but none flagged it "
            "as malicious."
        ),
        "summary.vt.malicious": "{count} security engines flagged this file as malicious.",
        "summary.vt.not_found": (
            "VirusTotal has not seen this file before — it may be new or rare."
        ),
        "summary.vt.no_key": "No VirusTotal query was made (no API key is configured).",
        "summary.vt.unauthorized": "Your VirusTotal key was rejected.",
        "summary.vt.rate_limited": "VirusTotal's rate limit was reached; try again shortly.",
        "summary.vt.network_error": (
            "The VirusTotal query failed because no internet connection could "
            "be made."
        ),
        "summary.vt.failed": "The VirusTotal query could not be completed.",

        # --- Summary bullets: signature -------------------------------------
        "summary.sig.signed_valid_by": (
            "The file is signed by {signer} and the signature is valid; that "
            "does not prove it is harmless."
        ),
        "summary.sig.signed_valid": (
            "The file has a valid digital signature; that does not prove it is "
            "harmless."
        ),
        "summary.sig.hash_mismatch": (
            "Careful: the file is signed, but its contents appear to have "
            "changed since it was signed (the hash does not match)."
        ),
        "summary.sig.untrusted": (
            "The file is signed, but the certificate chain could not be "
            "verified — the signature cannot be treated as trustworthy."
        ),
        "summary.sig.unsigned": "The file has no digital signature.",
        "summary.sig.not_applicable": "This kind of file cannot carry a digital signature.",

        # --- Summary bullets: local record ----------------------------------
        "summary.local.same": "Identical to the version you remembered earlier.",
        "summary.local.changed": (
            "Careful: this file looks different from the version you remembered."
        ),
        "summary.local.new": "This file's hash was added to the local record.",

        # --- Evidence rows: the source of each finding -----------------------
        "factor.name.virustotal": "VirusTotal",
        "factor.name.signature": "Digital Signature",
        "factor.name.local": "Local Record",

        "factor.vt.not_queried": "No query was made.",
        "factor.vt.no_analysing_engines": (
            "A result came back but no engine supplied data; not counted as a "
            "sign of safety."
        ),
        "factor.vt.malicious": "{count} security engines flagged it as malicious.",
        "factor.vt.suspicious": "{count} engines flagged it as suspicious.",
        "factor.vt.stale": (
            "The VirusTotal result is very old; not counted as current evidence "
            "of safety."
        ),
        "factor.vt.undated": (
            "The VirusTotal result could not be dated; not counted as current "
            "evidence of safety."
        ),
        "factor.vt.malformed": (
            "The VirusTotal engine statistics could not be read; not counted as "
            "a sign of safety."
        ),
        "factor.vt.clean": "No malicious or suspicious flag from {count} engines.",
        "factor.vt.not_found": (
            "This hash is not on VirusTotal — the file may be new or rare; that "
            "does not mean it is clean."
        ),
        "factor.vt.no_key": "No query could be made because no API key is configured.",
        "factor.vt.unauthorized": "The API key was rejected.",
        "factor.vt.rate_limited": "The rate limit was reached.",
        "factor.vt.network_error": "VirusTotal could not be reached.",
        "factor.vt.failed": "The query could not be completed.",
        "factor.vt.reported": "VirusTotal reported: {message}",

        "factor.sig.not_checked": "Not checked.",
        "factor.sig.signed_valid_by": "Valid digital signature: {signer}",
        "factor.sig.signed_valid": "The file has a valid digital signature.",
        "factor.sig.hash_mismatch": (
            "There is a signature, but the file's contents changed after it was "
            "signed (the hash does not match)."
        ),
        "factor.sig.untrusted": (
            "There is a signature, but the certificate chain could not be "
            "verified (not trustworthy)."
        ),
        "factor.sig.unsigned": "The file carries no digital signature.",
        "factor.sig.not_applicable": (
            "A signature check does not apply to this kind of file."
        ),
        "factor.sig.unsupported": "Not supported on this operating system.",
        "factor.sig.unknown": "The signature state could not be determined.",
        "factor.sig.reported": "The signature check reported: {message}",

        "factor.local.same": (
            "Identical to the version remembered earlier (not evidence of "
            "harmlessness)."
        ),
        "factor.local.changed": "The file differs from the version remembered earlier!",
        "factor.local.new": "This file's hash was added to the local record.",

        # --- Verify tab: what a manifest's signature establishes -------------
        "manifest.badge.unsigned": "Manifest is unsigned",
        "manifest.badge.unsigned.detail": (
            "This manifest was not signed. Where the reference hashes came from "
            "cannot be established; the manifest file may have been altered."
        ),
        "manifest.badge.embedded": "Signature valid — the signing key is not trusted",
        "manifest.badge.embedded.detail": (
            "The signature was verified with the key inside the manifest "
            "itself. That only shows the manifest is internally consistent: "
            "whoever altered it could have embedded their own key too. Supply "
            "the public key you trust to establish where it came from."
        ),
        "manifest.badge.trusted": "Verified with a trusted key",
        "manifest.badge.trusted.detail": (
            "The manifest's signature was verified with the trusted public key "
            "you supplied; its contents have not changed since it was signed."
        ),
        "manifest.badge.invalid": "Manifest signature is invalid",
        "manifest.badge.invalid.detail": (
            "The manifest's signature could not be verified. The manifest may "
            "have been tampered with; do not rely on the comparison results."
        ),
        "manifest.result.invalid": (
            "Manifest signature is invalid — the comparison result is not "
            "trustworthy."
        ),
        "manifest.result.mismatch": "Differences found — the files do not match the manifest.",
        "manifest.result.trusted": (
            "The files match a manifest verified with a trusted key."
        ),
        "manifest.result.embedded": (
            "The files match the manifest, but where the manifest came from was "
            "not established."
        ),
        "manifest.result.unsigned": (
            "The files match the manifest, but because the manifest is unsigned "
            "the reference data may have been altered."
        ),
        "report.doc.title": "File Trust Report",
        "report.doc.generated": "Generated",
        "report.doc.section.file": "File Details",
        "report.doc.section.hashes": "Hash Values",
        "report.doc.section.vt": "VirusTotal",
        "report.doc.section.signature": "Digital Signature",
        "report.doc.section.local": "Local Record",
        "report.doc.section.factors": "Risk Factors",
        "report.doc.no_factors": "The factor list is empty.",
        "report.doc.not_queried": "No query was made.",
        "report.doc.not_checked": "Not checked.",
        "report.doc.no_local": "No local record.",
        "report.doc.message": "Message",
        "report.err.json": "The JSON report could not be written: {error}",
        "report.err.html": "The HTML report could not be written: {error}",

        # ====================================================================
        # What the application says on its own account.
        #
        # The line these sit on: text the application *chose* is translated;
        # text that relays what the operating system, the filesystem or a
        # remote API reported is not. A diagnostic naming a PermissionError
        # loses the detail that makes it useful if it is rephrased, and
        # several are raised from the signing and key paths where a rewrite
        # for wording alone is a bad trade. tests/test_chosen_text.py holds
        # the modules on this side of the line to zero literals.
        # ====================================================================

        # --- Hash policy: refusals, confirmations, warnings ------------------
        "policy.output_overwrites_input": (
            "The save target is the file being hashed itself ({target}). "
            "Writing the manifest would destroy the file it describes. Choose "
            "a different target."
        ),
        "policy.sign_key_inside_folder": (
            "The signing key is inside the folder being scanned ({sign_key}). "
            "Anyone who receives the folder receives the key and can sign "
            "manifests in your name."
        ),
        "policy.sign_key_beside_manifest": (
            "The signing key is in the same folder as the manifest "
            "({sign_key}). A private key must not travel with the document it "
            "signs."
        ),
        "policy.insecure_algorithm": (
            "An integrity manifest is being built with {algo}. Producing a "
            "different file with the same digest is practical in that "
            "algorithm, so a digest that matches later does NOT PROVE the file "
            "is unchanged. Use it only for compatibility with old checksum "
            "lists. Safe choices: {safe}."
        ),
        "policy.manifest_inside_folder": (
            "The manifest is being written inside the folder being scanned "
            "({output}); it was excluded from its own inventory. Give the same "
            "path as the manifest when verifying, or it will show up as a new "
            "file."
        ),

        # --- Baseline: replacing the remembered version ----------------------
        "baseline.save": "Remember this version",
        "baseline.already_current": (
            "This file is already identical to the remembered version; there "
            "is nothing to do."
        ),
        "baseline.confirm_replace": (
            "This file is DIFFERENT from the version you remembered.\n\n"
            "If you make the new version the baseline you will not be able to "
            "compare against the previous one. Are you sure you expected this "
            "change?"
        ),
        "baseline.confirm_risky": (
            "This scan turned up signs worth paying attention to.\n\n"
            "Do you still want to record this version as the baseline?"
        ),
        "baseline.blocked": (
            "This file cannot be recorded as a baseline: the scan reports a "
            "security detection, high risk or a broken signature. Making a "
            "file an engine flagged into the \"known good version\" hides that "
            "detection permanently. Verify where the file came from first."
        ),

        # --- Local record: what the store says about a file ------------------
        "local.not_tracked": "This file has not been remembered before.",
        "local.same": "The file is identical to its remembered version.",
        "local.changed": "The file differs from its remembered version.",
        "local.recorded": "A new record was created for this file.",
        "local.updated": "The record was updated.",

        # --- Scan progress ---------------------------------------------------
        "pipeline.step.file_info": "Reading file details…",
        "pipeline.step.hashing": "Computing hashes…",
        "pipeline.step.virustotal": "Querying VirusTotal…",
        "pipeline.step.signature": "Checking the digital signature…",
        "pipeline.step.local": "Comparing against the local record…",
        "pipeline.step.recheck": "Re-verifying the file's integrity…",
        "pipeline.step.risk": "Assessing risk…",
        "pipeline.step.done": "Done.",

        # --- The file moved underneath the scan ------------------------------
        # A finding, not a relayed diagnostic: the tool detected this and chose
        # to say it, and it is the most security-relevant thing it can report
        # mid-scan.
        "pipeline.changed.unreadable": (
            "The file became unreadable during the scan: {path}"
        ),
        "pipeline.changed.metadata": "The file changed during the scan: {path}",
        "pipeline.changed.content": (
            "The file's contents changed during the scan: {path}"
        ),
        "startup.warning.title": "Data Warning",
        "startup.warning.body": (
            "Some records were not in the expected state when the application "
            "started:\n\n{lines}"
        ),
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
        "menu.tools": "Araçlar",
        "footer.studio": "torpilstudio.com",
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
            "Bir dosya seçin ya da bu pencereye sürükleyin — hemen taranır, "
            "sonuç burada görünür."
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

        # ====================================================================
        # Hükmün kendisi.
        #
        # `core/risk_engine.py` ve `core/smart_summary.py` hangisinin doğru
        # olduğuna karar verip anahtar döndürüyor; çekirdekte bu tabloyu okuyan
        # hiçbir şey yok. Metinler kodun zorlayamadığı bir kuralı taşıyor:
        # hiçbiri dosyanın güvenli olduğunu söylemiyor. Hiçbir araç bunu
        # kanıtlayamaz ve sessizce böyle bir söz veren bir çeviri, hiç
        # çevrilmemiş olmasından daha kötü bir kusur olurdu.
        # ====================================================================

        # --- Risk rozetinin üstündeki başlık ---------------------------------
        "risk.headline.low": "Güçlü bir risk işareti bulunamadı.",
        "risk.headline.medium": "Dikkatli olun — bazı şüpheli işaretler var.",
        "risk.headline.high": "Bu dosya şüpheli olabilir.",
        "risk.headline.unknown": "Bu dosya hakkında yeterli veri yok.",

        # --- Öğüt satırı ------------------------------------------------------
        "summary.advice.low": (
            "Bu, dosyanın kesinlikle güvenli olduğu anlamına gelmez — yalnızca "
            "güvendiğiniz kaynaklardan indirdiğiniz dosyaları açın."
        ),
        "summary.advice.medium": (
            "Dosyayı açmadan önce kaynağını ve indirme adresini bir kez daha "
            "doğrulamanızı öneririz."
        ),
        "summary.advice.high": (
            "Bu dosyayı çalıştırmamanızı öneririz. Şüpheli görünüyorsa silin "
            "ve indirildiği kaynağı tekrar incelemeden kullanmayın."
        ),
        "summary.advice.unknown": (
            "Daha net bir sonuç için Ayarlar'dan VirusTotal API anahtarınızı "
            "ekleyebilir veya dosyayı kaydederek ileride değişip değişmediğini "
            "izleyebilirsiniz."
        ),

        # --- Özet maddeleri: VirusTotal ---------------------------------------
        "summary.vt.no_usable_analysis": (
            "VirusTotal sonucu alındı ancak kullanılabilir motor analizi "
            "bulunamadı; bu bir güven işareti sayılamaz."
        ),
        "summary.vt.clean_but_stale": (
            "VirusTotal'da zararlı işareti yok, ancak bu sonuç çok eski; "
            "dosyanın şu anki hâli için güncel bir kanıt sayılmaz."
        ),
        "summary.vt.clean_but_undated": (
            "VirusTotal'da zararlı işareti yok, ancak bu sonucun tarihi "
            "belirsiz; dosyanın şu anki hâli için güncel bir kanıt sayılmaz."
        ),
        "summary.vt.clean": (
            "VirusTotal'daki güvenlik motorlarından zararlı veya şüpheli "
            "işareti gelmedi."
        ),
        "summary.vt.suspicious_only": (
            "{count} motor bu dosyayı şüpheli buldu, ama zararlı olarak "
            "işaretleyen yok."
        ),
        "summary.vt.malicious": "{count} güvenlik motoru bu dosyayı zararlı olarak işaretledi.",
        "summary.vt.not_found": (
            "VirusTotal bu dosyayı daha önce görmemiş — yeni veya nadir bir "
            "dosya olabilir."
        ),
        "summary.vt.no_key": "VirusTotal sorgusu yapılmadı (API anahtarı ayarlanmamış).",
        "summary.vt.unauthorized": "VirusTotal anahtarınız reddedildi.",
        "summary.vt.rate_limited": "VirusTotal hız limitine ulaşıldı, biraz sonra tekrar deneyin.",
        "summary.vt.network_error": (
            "İnternet bağlantısı kurulamadığı için VirusTotal sorgusu başarısız."
        ),
        "summary.vt.failed": "VirusTotal sorgusu tamamlanamadı.",

        # --- Özet maddeleri: imza ---------------------------------------------
        "summary.sig.signed_valid_by": (
            "Dosya {signer} tarafından imzalanmış (imza geçerli); bu, dosyanın "
            "zararsız olduğunu kanıtlamaz."
        ),
        "summary.sig.signed_valid": (
            "Dosyanın geçerli bir dijital imzası var; bu, zararsız olduğunu "
            "kanıtlamaz."
        ),
        "summary.sig.hash_mismatch": (
            "Dikkat: dosyanın imzası var ama içeriği imzalandıktan sonra "
            "değişmiş görünüyor (hash uyuşmuyor)."
        ),
        "summary.sig.untrusted": (
            "Dosyanın imzası var ama sertifika zinciri doğrulanamadı — imza "
            "güvenilir kabul edilemez."
        ),
        "summary.sig.unsigned": "Dosyanın dijital imzası yok.",
        "summary.sig.not_applicable": "Bu dosya türü dijital imza taşıyamıyor.",

        # --- Özet maddeleri: yerel kayıt --------------------------------------
        "summary.local.same": "Daha önce kaydettiğiniz sürümle birebir aynı.",
        "summary.local.changed": (
            "Dikkat: bu dosya daha önce kaydettiğiniz sürümden farklı görünüyor."
        ),
        "summary.local.new": "Bu dosyanın hash'i yerel kayda eklendi.",

        # --- Kanıt satırları: her bulgunun kaynağı ----------------------------
        "factor.name.virustotal": "VirusTotal",
        "factor.name.signature": "Dijital İmza",
        "factor.name.local": "Yerel Kayıt",

        "factor.vt.not_queried": "Sorgu yapılmadı.",
        "factor.vt.no_analysing_engines": (
            "Sonuç döndü ama hiçbir motor veri vermedi; güven sinyali sayılmadı."
        ),
        "factor.vt.malicious": "{count} güvenlik motoru zararlı olarak işaretledi.",
        "factor.vt.suspicious": "{count} motor şüpheli olarak işaretledi.",
        "factor.vt.stale": (
            "VirusTotal sonucu çok eski; güncel bir güven sinyali sayılmadı."
        ),
        "factor.vt.undated": (
            "VirusTotal sonucunun tarihi belirlenemedi; güncel bir güven "
            "sinyali sayılmadı."
        ),
        "factor.vt.malformed": (
            "VirusTotal motor istatistikleri okunamadı; güven sinyali sayılmadı."
        ),
        "factor.vt.clean": "{count} motorda zararlı/şüpheli işareti yok.",
        "factor.vt.not_found": (
            "Bu hash VirusTotal'da yok — dosya yeni veya nadir olabilir; temiz "
            "olduğu anlamına gelmez."
        ),
        "factor.vt.no_key": "API anahtarı ayarlanmadığı için sorgu yapılamadı.",
        "factor.vt.unauthorized": "API anahtarı reddedildi.",
        "factor.vt.rate_limited": "Hız limitine takıldı.",
        "factor.vt.network_error": "VirusTotal'a ulaşılamadı.",
        "factor.vt.failed": "Sorgu tamamlanamadı.",
        "factor.vt.reported": "VirusTotal bildirdi: {message}",

        "factor.sig.not_checked": "Kontrol yapılmadı.",
        "factor.sig.signed_valid_by": "Geçerli dijital imza: {signer}",
        "factor.sig.signed_valid": "Dosyanın geçerli bir dijital imzası var.",
        "factor.sig.hash_mismatch": (
            "İmza var ama dosya içeriği imzalandıktan sonra değişmiş (hash "
            "uyuşmuyor)."
        ),
        "factor.sig.untrusted": (
            "İmza var ama sertifika zinciri doğrulanamadı (güvenilir değil)."
        ),
        "factor.sig.unsigned": "Dosyada dijital imza yok.",
        "factor.sig.not_applicable": "Bu dosya türü için imza kontrolü uygulanamaz.",
        "factor.sig.unsupported": "Bu işletim sisteminde desteklenmiyor.",
        "factor.sig.unknown": "İmza durumu belirlenemedi.",
        "factor.sig.reported": "İmza kontrolü bildirdi: {message}",

        "factor.local.same": (
            "Daha önce kaydedilen sürümle birebir aynı (zararlılık kanıtı değil)."
        ),
        "factor.local.changed": "Dosya daha önce kaydedilen sürümden farklı!",
        "factor.local.new": "Bu dosyanın hash'i yerel kayda eklendi.",

        # --- Doğrula sekmesi: manifest imzasının ne kanıtladığı ---------------
        "manifest.badge.unsigned": "Manifest imzasız",
        "manifest.badge.unsigned.detail": (
            "Bu manifest imzalanmamış. Referans hash'lerin kaynağı doğrulanamaz; "
            "manifest dosyası değiştirilmiş olabilir."
        ),
        "manifest.badge.embedded": "İmza geçerli — kaynak anahtar güvenilmiyor",
        "manifest.badge.embedded.detail": (
            "İmza, manifestin kendi içindeki anahtarla doğrulandı. Bu yalnızca "
            "manifestin kendi içinde tutarlı olduğunu gösterir: manifesti "
            "değiştiren biri kendi anahtarını da gömebilirdi. Kaynağı "
            "doğrulamak için güvendiğiniz genel anahtarı kullanın."
        ),
        "manifest.badge.trusted": "Güvenilen anahtarla doğrulandı",
        "manifest.badge.trusted.detail": (
            "Manifest imzası, sağladığınız güvenilen genel anahtarla "
            "doğrulandı; içeriği imzalandığından beri değişmemiş."
        ),
        "manifest.badge.invalid": "Manifest imzası geçersiz",
        "manifest.badge.invalid.detail": (
            "Manifestin imzası doğrulanamadı. Manifest kurcalanmış olabilir; "
            "karşılaştırma sonuçlarına güvenmeyin."
        ),
        "manifest.result.invalid": (
            "Manifest imzası geçersiz — karşılaştırma sonucu güvenilir değil."
        ),
        "manifest.result.mismatch": "Farklılıklar bulundu — dosyalar manifestle eşleşmiyor.",
        "manifest.result.trusted": (
            "Dosyalar, güvenilen anahtarla doğrulanmış manifestle eşleşiyor."
        ),
        "manifest.result.embedded": (
            "Dosyalar manifestle eşleşiyor; ancak manifestin kaynağı doğrulanmadı."
        ),
        "manifest.result.unsigned": (
            "Dosyalar manifestle eşleşiyor; ancak manifest imzasız olduğu için "
            "referans veriler değiştirilmiş olabilir."
        ),
        "report.doc.title": "Dosya Güven Raporu",
        "report.doc.generated": "Oluşturulma",
        "report.doc.section.file": "Dosya Bilgileri",
        "report.doc.section.hashes": "Hash Değerleri",
        "report.doc.section.vt": "VirusTotal",
        "report.doc.section.signature": "Dijital İmza",
        "report.doc.section.local": "Yerel Kayıt",
        "report.doc.section.factors": "Risk Faktörleri",
        "report.doc.no_factors": "Faktör listesi boş.",
        "report.doc.not_queried": "Sorgu yapılmadı.",
        "report.doc.not_checked": "Kontrol yapılmadı.",
        "report.doc.no_local": "Yerel kayıt yok.",
        "report.doc.message": "Mesaj",
        "report.err.json": "JSON rapor yazılamadı: {error}",
        "report.err.html": "HTML rapor yazılamadı: {error}",

        # ====================================================================
        # Uygulamanın kendi adına söyledikleri.
        #
        # Sınır şu: uygulamanın **seçtiği** metin çevrilir; işletim sisteminin,
        # dosya sisteminin ya da uzak bir API'nin bildirdiğini aktaran metin
        # çevrilmez. Bir `PermissionError`'ı adlandıran tanı metni yeniden
        # yazılırsa onu yararlı kılan ayrıntıyı kaybeder; ayrıca bunların bir
        # kısmı imzalama ve anahtar yollarında ve salt ifade için oraya
        # dokunmak kötü bir takas. `tests/test_chosen_text.py` bu tarafta kalan
        # modülleri sıfır dizede tutuyor.
        # ====================================================================

        # --- Hash politikası: ret, onay, uyarı -------------------------------
        "policy.output_overwrites_input": (
            "Kaydetme hedefi özetlenecek dosyanın kendisi ({target}). Manifest "
            "yazılsaydı özetlenen dosya yok olurdu. Farklı bir hedef seçin."
        ),
        "policy.sign_key_inside_folder": (
            "İmzalama anahtarı taranan klasörün içinde ({sign_key}). Klasörü "
            "alan herkes anahtarı da alır ve sizin adınıza manifest imzalayabilir."
        ),
        "policy.sign_key_beside_manifest": (
            "İmzalama anahtarı manifestle aynı klasörde ({sign_key}). Özel "
            "anahtar, imzaladığı belgeyle birlikte dağıtılmamalı."
        ),
        "policy.insecure_algorithm": (
            "{algo} ile bütünlük manifesti üretiliyor. Bu algoritmada aynı "
            "özeti veren farklı bir dosya üretmek pratiktir; sonradan eşleşen "
            "bir özet, dosyanın değiştirilmediğini KANITLAMAZ. Yalnız eski "
            "checksum listeleriyle uyum için kullanın. Güvenli seçenekler: {safe}."
        ),
        "policy.manifest_inside_folder": (
            "Manifest taranan klasörün içine yazılıyor ({output}); kendi "
            "envanterinden hariç tutuldu. Doğrularken aynı yolu manifest olarak "
            "verin, aksi hâlde 'yeni dosya' görünür."
        ),

        # --- Temel sürüm: kaydedilmiş sürümü değiştirmek ---------------------
        "baseline.save": "Bu sürümü hatırla",
        "baseline.already_current": (
            "Bu dosya zaten kayıtlı sürümle aynı; yapılacak bir şey yok."
        ),
        "baseline.confirm_replace": (
            "Bu dosya daha önce kaydettiğiniz sürümden FARKLI.\n\n"
            "Yeni sürümü temel sürüm yaparsanız, önceki sürümle karşılaştırma "
            "yapamazsınız. Değişikliği beklediğinizden emin misiniz?"
        ),
        "baseline.confirm_risky": (
            "Bu taramada dikkat edilmesi gereken işaretler var.\n\n"
            "Yine de bu sürümü temel sürüm olarak kaydetmek istiyor musunuz?"
        ),
        "baseline.blocked": (
            "Bu dosya temel sürüm olarak kaydedilemez: tarama bir güvenlik "
            "tespiti, yüksek risk ya da bozuk imza bildiriyor. Bir motorun "
            "işaretlediği dosyayı 'bilinen iyi sürüm' yapmak, tespiti kalıcı "
            "olarak görünmez kılar. Önce dosyanın kaynağını doğrulayın."
        ),

        # --- Yerel kayıt: deponun dosya hakkında söyledikleri -----------------
        "local.not_tracked": "Bu dosya daha önce kaydedilmemiş.",
        "local.same": "Dosya kayıtlı sürümüyle aynı.",
        "local.changed": "Dosya kayıtlı sürümünden farklı.",
        "local.recorded": "Yeni dosya kaydı oluşturuldu.",
        "local.updated": "Kayıt güncellendi.",

        # --- Tarama ilerlemesi ------------------------------------------------
        "pipeline.step.file_info": "Dosya bilgileri okunuyor…",
        "pipeline.step.hashing": "Hash değerleri hesaplanıyor…",
        "pipeline.step.virustotal": "VirusTotal sorgulanıyor…",
        "pipeline.step.signature": "Dijital imza kontrol ediliyor…",
        "pipeline.step.local": "Yerel kayıt karşılaştırılıyor…",
        "pipeline.step.recheck": "Dosya bütünlüğü yeniden doğrulanıyor…",
        "pipeline.step.risk": "Risk değerlendiriliyor…",
        "pipeline.step.done": "Tamamlandı.",

        # --- Dosya tarama sırasında değişti -----------------------------------
        # Aktarılan bir tanı değil, bir bulgu: bunu araç tespit etti ve söylemeyi
        # seçti; tarama ortasında söyleyebileceği en güvenlik-kritik şey.
        "pipeline.changed.unreadable": (
            "Dosya tarama sırasında erişilemez oldu: {path}"
        ),
        "pipeline.changed.metadata": "Dosya tarama sırasında değişti: {path}",
        "pipeline.changed.content": (
            "Dosya içeriği tarama sırasında değişti: {path}"
        ),
        "startup.warning.title": "Veri Uyarısı",
        "startup.warning.body": (
            "Uygulama başlarken bazı kayıtlar beklenen durumda değildi:\n\n{lines}"
        ),
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
