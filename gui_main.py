"""
GUI entry point — this is the file PyInstaller wraps into HashToolGUI.exe.

Double-click the built executable to open the graphical interface. All CLI
functionality (hash / verify / report) is available through the **Araçlar**
menu; no terminal required.

Explorer's context-menu entry launches this with ``--verify "<file>"``, which
opens the window on that file and scans it straight away.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

from gui.app import run


def parse_args(argv: Sequence[str]) -> Optional[str]:
    """
    The file to scan on startup, or None to open on an empty screen.

    Hand-rolled rather than argparse, because argparse answers a command line
    it dislikes by printing usage and raising SystemExit. This is a windowed
    build: there is no console for the usage text to appear in, so the user
    would launch the app and see nothing happen at all. Anything unrecognised
    is dropped and the window opens.
    """
    args = list(argv)
    if len(args) >= 2 and args[0] == "--verify":
        return args[1]
    return None


if __name__ == "__main__":
    sys.exit(run(initial_path=parse_args(sys.argv[1:])))
