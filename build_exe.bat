@echo off
REM ----------------------------------------------------------------------
REM Build a single-file Windows executable for the Hash Verification Tool.
REM
REM Output:  dist\HashTool.exe   (~8 MB, no Python install required to run)
REM
REM Re-run this any time you change the source code.
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
echo === [2/3] Cleaning previous CLI build artefacts ===
if exist build\HashTool rmdir /s /q build\HashTool
if exist dist\HashTool.exe del /q dist\HashTool.exe
if exist HashTool.spec del /q HashTool.spec

echo.
echo === [3/3] Building HashTool.exe ===
python -m PyInstaller ^
    --onefile ^
    --console ^
    --clean ^
    --name HashTool ^
    main.py || goto :error

echo.
echo ============================================================
echo  Build OK.  Run:  dist\HashTool.exe --help
echo ============================================================
pause
exit /b 0

:error
echo.
echo *** Build failed. Check the output above. ***
pause
exit /b 1
