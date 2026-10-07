$ErrorActionPreference = 'Stop'
$taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskPrincipal = [Security.Principal.WindowsPrincipal]::new($taskIdentity)
if (-not $taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run Enable Packet Lens Network Access.cmd as administrator to allow the app through Windows Firewall.'
}
$taskNode = (Get-Command node -ErrorAction Stop).Source
$taskExisting = Get-NetFirewallRule -Name 'PacketLens-LAN-8876' -ErrorAction SilentlyContinue
if ($taskExisting) {
  $taskExisting | Format-List Name,Enabled,Profile,Direction,Action
  $taskExisting | Get-NetFirewallPortFilter | Format-List Protocol,LocalPort
  $taskExisting | Get-NetFirewallAddressFilter | Format-List RemoteAddress
  $taskExisting | Get-NetFirewallApplicationFilter | Format-List Program
  Write-Output 'A Packet Lens firewall rule already exists. Its settings are shown above; no changes were made.'
  exit 0
}
New-NetFirewallRule -Name 'PacketLens-LAN-8876' -DisplayName 'Packet Lens - local network' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8876 -Program $taskNode -Profile Domain,Private -RemoteAddress LocalSubnet | Format-List Name,Enabled,Profile,Direction,Action
Write-Output 'Packet Lens is allowed on TCP port 8876 from local subnets on Domain and Private networks.'
