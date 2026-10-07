@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required to run the local app.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:8876 in your browser once the server is ready.
node serve.mjs
pause
