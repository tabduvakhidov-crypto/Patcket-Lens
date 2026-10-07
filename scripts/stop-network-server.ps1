$ErrorActionPreference = 'Stop'
$taskApp = Split-Path -Parent $PSScriptRoot
$taskPidFile = Join-Path $taskApp '.runtime/network-server.json'
if (-not (Test-Path -LiteralPath $taskPidFile)) {
  Write-Output 'No background Packet Lens server is recorded. For a console server, press Ctrl+C in its window.'
  exit 0
}
$taskState = Get-Content -LiteralPath $taskPidFile -Raw | ConvertFrom-Json
$taskProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$taskState.pid)"
if (-not $taskProcess) {
  Write-Output 'The recorded Packet Lens server is already stopped.'
  exit 0
}
$taskScript = Join-Path $taskApp 'serve.mjs'
if ($taskProcess.Name -ne 'node.exe' -or -not $taskProcess.CommandLine.Contains($taskScript) -or -not $taskProcess.CommandLine.Contains('--lan')) {
  throw 'The recorded process is not the Packet Lens network server; no process was stopped.'
}
if ($taskProcess.CreationDate.ToUniversalTime().ToString('o') -ne $taskState.creationTime) {
  throw 'The recorded process identity changed; no process was stopped.'
}
Stop-Process -Id ([int]$taskState.pid)
Write-Output 'Packet Lens network server stopped.'
