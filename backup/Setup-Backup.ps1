<#
.SYNOPSIS
    One-time setup for automatic Bitwarden vault backups.

.DESCRIPTION
    Asks for your Bitwarden API key, master password and a backup file
    password, stores them encrypted with Windows DPAPI (readable only by your
    Windows account on this PC), schedules a daily backup and runs the first
    one straight away.

.EXAMPLE
    .\Setup-Backup.ps1

.EXAMPLE
    .\Setup-Backup.ps1 -Destination "$env:OneDrive\Bitwarden Backups", 'E:\Backups' -Keep 60 -Time '12:30'

.EXAMPLE
    .\Setup-Backup.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    # Folders to save backups to. The first is the main one; the rest get copies.
    [string[]]$Destination,

    # How many backups to keep in each folder.
    [int]$Keep = 30,

    # Daily backup time (24h). Runs at next logon if the PC was off.
    [string]$Time = '02:00',

    # Removes the scheduled task and stored credentials. Leaves backups alone.
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$taskName     = 'Bitwarden Vault Backup'
$configDir    = Join-Path $env:LOCALAPPDATA 'BitwardenBackup'
$configPath   = Join-Path $configDir 'config.json'
$secretsPath  = Join-Path $configDir 'secrets.xml'
$backupScript = Join-Path $PSScriptRoot 'Backup-Vault.ps1'

function ConvertTo-PlainText([securestring]$Secure) {
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $secretsPath, $configPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Scheduled task and stored credentials removed. Your backup files were not touched.'
    return
}

$bwCmd = Get-Command bw.cmd -ErrorAction SilentlyContinue
if (-not $bwCmd) { $bwCmd = Get-Command bw -ErrorAction SilentlyContinue }
if (-not $bwCmd) { throw 'Bitwarden CLI not found. Install it with: npm install -g @bitwarden/cli' }
$bwPath = $bwCmd.Source

if (-not $Destination) {
    $baseDir = if ($env:OneDrive) { $env:OneDrive } else { [Environment]::GetFolderPath('MyDocuments') }
    $Destination = @(Join-Path $baseDir 'Bitwarden Backups')
}

Write-Host ''
Write-Host '=== Bitwarden backup setup ===' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Which Bitwarden server is your account on?'
Write-Host '  1) bitwarden.com (US) - the default'
Write-Host '  2) bitwarden.eu (EU)'
Write-Host '  3) Self-hosted (e.g. Vaultwarden)'
$choice = Read-Host 'Choose 1, 2 or 3 [1]'
$serverUrl = switch ($choice) {
    '2'     { 'https://vault.bitwarden.eu' }
    '3'     { Read-Host 'Server URL (e.g. https://vault.example.com)' }
    default { 'https://vault.bitwarden.com' }
}

# The CLI only lets you change server while logged out.
$ErrorActionPreference = 'Continue'
& $bwPath logout 2>&1 | Out-Null
& $bwPath config server $serverUrl 2>&1 | Out-Null
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw "Could not set Bitwarden server to $serverUrl" }

Write-Host ''
Write-Host 'Get your API key from the Bitwarden web vault:'
Write-Host '  Settings > Security > Keys > View API key'
$clientId     = Read-Host 'client_id' -AsSecureString
$clientSecret = Read-Host 'client_secret' -AsSecureString

Write-Host ''
$masterPassword = Read-Host 'Bitwarden master password' -AsSecureString

Write-Host ''
Write-Host 'Now choose a password for the backup files.'
Write-Host 'Make it different from your master password and WRITE IT DOWN -'
Write-Host 'without it the backups cannot be restored.' -ForegroundColor Yellow
while ($true) {
    $backupPassword = Read-Host 'Backup file password (12+ characters)' -AsSecureString
    $confirm        = Read-Host 'Confirm backup file password' -AsSecureString
    $plain = ConvertTo-PlainText $backupPassword
    if ($plain.Length -lt 12) {
        Write-Host 'Too short - use at least 12 characters.' -ForegroundColor Red
    }
    elseif ($plain -cne (ConvertTo-PlainText $confirm)) {
        Write-Host 'Passwords did not match, try again.' -ForegroundColor Red
    }
    elseif ($plain -ceq (ConvertTo-PlainText $masterPassword)) {
        Write-Host 'Please use a different password from your master password.' -ForegroundColor Red
    }
    else { break }
}
$plain = $null

New-Item -ItemType Directory -Force -Path $configDir | Out-Null

# Export-Clixml encrypts SecureStrings with DPAPI for the current user.
[pscustomobject]@{
    ClientId       = $clientId
    ClientSecret   = $clientSecret
    MasterPassword = $masterPassword
    BackupPassword = $backupPassword
} | Export-Clixml -Path $secretsPath

@{
    BwPath       = $bwPath
    ServerUrl    = $serverUrl
    Destinations = @($Destination)
    Keep         = $Keep
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backupScript`""
$trigger  = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Daily password-protected export of the Bitwarden vault.' -Force | Out-Null

Write-Host ''
Write-Host "Scheduled '$taskName' daily at $Time." -ForegroundColor Green
Write-Host "Backups go to: $($Destination -join ', ')"
Write-Host ''
Write-Host 'Running the first backup now...' -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript
if ($LASTEXITCODE -eq 0) {
    Write-Host 'All set! Your vault will now be backed up every day.' -ForegroundColor Green
}
else {
    Write-Host "First backup failed - see the log in $configDir\logs" -ForegroundColor Red
}
