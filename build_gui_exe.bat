@echo off
REM ----------------------------------------------------------------------
REM Build a single-file Windows GUI executable (no console window).
REM
REM Output:  dist\HashToolGUI.exe
REM
REM Double-click the built file to launch the graphical interface.
REM ----------------------------------------------------------------------

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
python -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --clean ^
    --name HashToolGUI ^
    gui_main.py || goto :error

echo.
echo ============================================================
echo  Build OK.  Double-click:  dist\HashToolGUI.exe
echo ============================================================
exit /b 0

:error
echo.
echo *** Build failed. Check the output above. ***
exit /b 1
