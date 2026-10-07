@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -File "%~dp0scripts\enable-network-access.ps1"
echo.
pause
