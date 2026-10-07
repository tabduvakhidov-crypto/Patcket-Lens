@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required to run the network server.
  pause
  exit /b 1
)
echo Starting Packet Lens for other computers on your network.
echo Share the network link printed below and keep this window open.
node serve.mjs --lan
pause
