@echo off
REM ----------------------------------------------------------------------
REM Build a single-file Windows GUI executable (no console window).
REM
REM Output:  dist\HashToolGUI.exe
REM
REM Double-click the built file to launch the graphical interface.
REM ----------------------------------------------------------------------

cd /d "%~dp0"
setlocal

REM The project's own interpreter, not whatever `python` PATH resolves to.
REM A bundle is built from the interpreter that runs PyInstaller, so the
REM wrong one silently produces an EXE missing the dependencies.
set "PY=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"

echo.
echo === [1/4] Checking PyInstaller  (%PY%) ===
"%PY%" -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    "%PY%" -m pip install -r requirements-dev.txt || goto :error
)

echo.
echo === [2/4] Cleaning previous GUI build artefacts ===
if exist build\HashToolGUI rmdir /s /q build\HashToolGUI
if exist dist\HashToolGUI.exe del /q dist\HashToolGUI.exe
if exist HashToolGUI.spec del /q HashToolGUI.spec

echo.
echo === [3/4] Building HashToolGUI.exe ===
REM This used to pass fifteen --hidden-import flags, explained by a comment
REM saying the gui.views.* widgets were "dynamically loaded". They are not:
REM there is no importlib, no __import__, no import_module anywhere in the
REM source. The flags were checked rather than trusted — the same build run
REM with and without them produces bundles containing the identical set of
REM 510 modules, requests, windnd and colorama included, because PyInstaller
REM reads imports inside functions and try/except blocks too. So they are
REM gone, and the way to re-check after a refactor is to build twice and
REM diff build\HashToolGUI\PYZ-00.toc against the flagless one.
"%PY%" -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --clean ^
    --noconfirm ^
    --name HashToolGUI ^
    gui_main.py || goto :error

echo.
echo === [4/4] Opening it, to see that it opens ===
REM A windowed build has nowhere to print an import error: it either shows a
REM window or fails in silence. This launches it, finds its window through
REM Win32, reads the version out of the title bar and closes it again.
"%PY%" tools\verify_exe_smoke.py --gui || goto :smokefail

echo.
echo ============================================================
echo  Build OK and verified.  Double-click:  dist\HashToolGUI.exe
echo ============================================================
pause
exit /b 0

:smokefail
echo.
echo *** The EXE was built but its window did not check out. ***
echo *** Read the output above before shipping it.           ***
pause
exit /b 1

:error
echo.
echo *** Build failed. Check the output above. ***
pause
exit /b 1
