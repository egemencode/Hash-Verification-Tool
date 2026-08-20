@echo off
REM ----------------------------------------------------------------------
REM Build a single-file Windows executable for the Hash Verification Tool.
REM
REM Output:  dist\HashTool.exe   (no Python install required to run)
REM
REM Re-run this any time you change the source code — and note that the
REM version string alone will not tell you whether you did. The build that
REM sat in dist\ before v2.0.0 answered --version with the same number as
REM its replacement while missing three subcommands and two refusals, which
REM is why step [4/4] exists.
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
echo === [2/4] Cleaning previous CLI build artefacts ===
if exist build\HashTool rmdir /s /q build\HashTool
if exist dist\HashTool.exe del /q dist\HashTool.exe
if exist HashTool.spec del /q HashTool.spec

echo.
echo === [3/4] Building HashTool.exe ===
"%PY%" -m PyInstaller ^
    --onefile ^
    --console ^
    --clean ^
    --noconfirm ^
    --name HashTool ^
    main.py || goto :error

echo.
echo === [4/4] Checking the executable, not just the build ===
"%PY%" tools\verify_exe_smoke.py || goto :smokefail

echo.
echo ============================================================
echo  Build OK and verified.  Run:  dist\HashTool.exe --help
echo ============================================================
pause
exit /b 0

:smokefail
echo.
echo *** The EXE was built but does not behave like the source. ***
echo *** Read the scenario list above before shipping it.       ***
pause
exit /b 1

:error
echo.
echo *** Build failed. Check the output above. ***
pause
exit /b 1
