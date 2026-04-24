"""
GUI entry point — this is the file PyInstaller wraps into HashToolGUI.exe.

Double-click the built executable to open the graphical interface. All
CLI functionality (hash / verify / report) is available through three
tabs; no terminal required.
"""

from __future__ import annotations

import sys

from gui.app import run


if __name__ == "__main__":
    sys.exit(run())
