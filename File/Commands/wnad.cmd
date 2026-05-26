@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "WNAD_DIR=%SCRIPT_DIR%Tools\Wifi\WNAD"
set "WNAD_PY=%WNAD_DIR%\wnad.py"

if not exist "%WNAD_PY%" (
    echo [!!] WNAD main program not found
    echo Expected: %WNAD_PY%
    pause
    exit /b 1
)

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [!!] Python not found. Install Python 3 first.
    pause
    exit /b 1
)

python "%WNAD_PY%" %*
