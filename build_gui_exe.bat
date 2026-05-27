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

echo.
echo === [1/3] Checking PyInstaller ===
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    python -m pip install --upgrade pyinstaller || goto :error
)

echo.
echo === [2/3] Cleaning previous GUI build artefacts ===
if exist build\HashToolGUI rmdir /s /q build\HashToolGUI
if exist dist\HashToolGUI.exe del /q dist\HashToolGUI.exe
if exist HashToolGUI.spec del /q HashToolGUI.spec

echo.
echo === [3/3] Building HashToolGUI.exe ===
REM Hidden imports cover modules pulled in via try/except (requests,
REM windnd, colorama) and the dynamically-loaded gui.views.* widgets
REM so PyInstaller's static analysis does not miss them.
python -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --clean ^
    --name HashToolGUI ^
    --hidden-import gui.views.trust_check_view ^
    --hidden-import gui.views.history_view ^
    --hidden-import gui.views.settings_view ^
    --hidden-import core.trust_pipeline ^
    --hidden-import core.trust_report ^
    --hidden-import core.vt_client ^
    --hidden-import core.signature_checker ^
    --hidden-import core.local_verify ^
    --hidden-import core.history_manager ^
    --hidden-import core.risk_engine ^
    --hidden-import core.smart_summary ^
    --hidden-import core.file_info ^
    --hidden-import requests ^
    --hidden-import windnd ^
    --hidden-import colorama ^
    gui_main.py || goto :error

echo.
echo ============================================================
echo  Build OK.  Double-click:  dist\HashToolGUI.exe
echo ============================================================
pause
exit /b 0

:error
echo.
echo *** Build failed. Check the output above. ***
pause
exit /b 1
