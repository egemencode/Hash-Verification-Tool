"""
The "Bu dosyayı doğrula" entry in Explorer's context menu.

Windows keeps per-user shell verbs under HKEY_CURRENT_USER, which is what
this module writes: no administrator prompt, nothing that touches another
account, and one key to delete to undo all of it.

On Windows 11 the entry lands in the classic menu, behind "Show more
options" (Shift+F10 opens it directly). Reaching the short first-level menu
needs an IExplorerCommand handler in a package with an identity — an MSIX or
sparse package, signed — which a PyInstaller build has no way to be.
"""

from __future__ import annotations

from typing import Optional


def build_command(executable: str, *, script: Optional[str] = None) -> str:
    """
    The command line Explorer runs for the clicked file.

    Both paths are quoted, and so is the ``%1`` placeholder. The shell hands
    this over as a single line and splits it on spaces: unquoted, a program
    in ``C:\\Program Files`` becomes two arguments, and a file named
    ``my report.pdf`` becomes two more. Either way the entry does nothing,
    with no error to explain it.

    *script* is for running from a source checkout, where the executable is
    the interpreter and the script is a separate argument. A frozen build
    passes only the executable.
    """
    parts = [f'"{executable}"']
    if script:
        parts.append(f'"{script}"')
    parts.append("--verify")
    parts.append('"%1"')
    return " ".join(parts)


# Where the per-user verb lives. "*" means every file; the tool answers
# questions about documents and archives as readily as about executables,
# and a curated extension list is a list that is always missing one — the
# file that prompted this feature was an .apk.
MENU_BASE = r"Software\Classes\*\shell\VerifyWithHashTool"


def _hkcu():
    import winreg

    return winreg.HKEY_CURRENT_USER


def register(
    executable: str,
    label: str,
    *,
    script: Optional[str] = None,
    base: str = MENU_BASE,
) -> None:
    """
    Create (or refresh) the context-menu entry.

    Writing over an existing entry is the normal case, not an error: the
    executable may have moved since it was last registered, and a menu that
    calls a path nothing lives at any more is worse than no menu.
    """
    import winreg

    command = build_command(executable, script=script)
    with winreg.CreateKey(_hkcu(), base) as key:
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, label)
        # The shell reads the icon from the executable itself, so it keeps
        # working when the app is rebuilt.
        winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f"{executable},0")
    with winreg.CreateKey(_hkcu(), base + r"\command") as key:
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, command)


def unregister(*, base: str = MENU_BASE) -> None:
    """
    Remove the entry, leaving nothing behind.

    Deletes the ``command`` subkey first: Windows refuses to delete a key
    that still has children, and a half-removed entry shows up in the menu
    as a command that does nothing. Absent keys are not an error — this runs
    whenever the setting is turned off, including when it was never on.
    """
    import winreg

    for path in (base + r"\command", base):
        try:
            winreg.DeleteKey(_hkcu(), path)
        except FileNotFoundError:
            pass


def _read(path: str) -> Optional[str]:
    import winreg

    try:
        with winreg.OpenKey(_hkcu(), path) as key:
            value, _kind = winreg.QueryValueEx(key, None)
            return str(value)
    except FileNotFoundError:
        return None


def registered_command(*, base: str = MENU_BASE) -> Optional[str]:
    """The command Explorer would run, or None if there is no entry."""
    return _read(base + r"\command")


def registered_label(*, base: str = MENU_BASE) -> Optional[str]:
    """The text shown in the menu, or None if there is no entry."""
    return _read(base)


def is_registered(*, base: str = MENU_BASE) -> bool:
    return registered_command(base=base) is not None


def launch_target() -> tuple[str, Optional[str]]:
    """
    What Explorer should run: ``(executable, script)``.

    A PyInstaller build is the executable. A source checkout is the
    interpreter plus ``gui_main.py`` — and it is ``pythonw.exe`` that gets
    written, not ``python.exe``, so a right-click does not flash a console
    window behind the app.
    """
    import sys
    from pathlib import Path

    if getattr(sys, "frozen", False):
        return sys.executable, None

    interpreter = Path(sys.executable)
    windowless = interpreter.with_name("pythonw.exe")
    if windowless.is_file():
        interpreter = windowless
    script = Path(__file__).resolve().parent.parent / "gui_main.py"
    return str(interpreter), str(script)


def sync(
    enabled: bool,
    label: str,
    *,
    executable: Optional[str] = None,
    script: Optional[str] = None,
    base: str = MENU_BASE,
) -> None:
    """
    Make the registry agree with the setting.

    The one call the application makes — at startup and whenever the setting
    or the language changes. Startup matters as much as the toggle: the entry
    stores an absolute path, so moving the executable leaves a menu item that
    calls somewhere nothing lives. Re-running this repairs it silently.

    Writes only when something actually differs, so the common case (started,
    nothing changed) touches no keys at all.
    """
    if not enabled:
        unregister(base=base)
        return

    if executable is None:
        executable, script = launch_target()

    desired = build_command(executable, script=script)
    if registered_command(base=base) == desired and registered_label(base=base) == label:
        return
    register(executable, label, script=script, base=base)
