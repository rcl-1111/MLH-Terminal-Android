@echo off
chcp 65001 >nul
title MLH-Terminal Windows
cd /d "%~dp0"

set "MLH_ROOT=%~dp0"
set "MLH_COMMANDS=%MLH_ROOT%File\Commands"
set "MLH_DATA=%MLH_ROOT%Data"
set "PATH=%MLH_COMMANDS%;%PATH%"

cls
echo ===============================================
echo       MLH-Terminal  Windows  Environment
echo ===============================================
echo.
echo  [*] Root:     %MLH_ROOT%
echo  [*] Commands: %MLH_COMMANDS%
echo  [*] Data:     %MLH_DATA%
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
    echo  [OK] Python ready
) else (
    echo  [!!] Python not found. Install Python 3 first.
    echo.
    pause
    exit /b 1
)

echo  [OK] Command directory added to PATH
echo.
echo  Available commands:
echo    wnad              WNAD Wireless Network Attack and Defense
echo    netcheck          Network detection tool
echo.
echo  Type "exit" to leave
echo.
echo ===============================================
echo.

cmd /k "prompt MLH $P$G"
