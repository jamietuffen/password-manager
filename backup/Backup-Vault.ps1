<#
.SYNOPSIS
    Creates a password-protected, encrypted export of your Bitwarden vault.

.DESCRIPTION
    Run Setup-Backup.ps1 once first. After that this script runs unattended
    (normally from Task Scheduler) using the credentials Setup-Backup.ps1
    stored with Windows DPAPI, so only your Windows account can read them.

    Each run:
      1. Logs in with your API key (only if the CLI isn't logged in yet)
      2. Unlocks the vault and syncs the latest data
      3. Exports it as password-protected encrypted JSON
      4. Checks the file really is encrypted, then copies it to every destination
      5. Deletes old backups beyond the retention count
      6. Locks the vault and clears secrets from memory
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$configDir   = Join-Path $env:LOCALAPPDATA 'BitwardenBackup'
$configPath  = Join-Path $configDir 'config.json'
$secretsPath = Join-Path $configDir 'secrets.xml'
$logDir      = Join-Path $configDir 'logs'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    $logFile = Join-Path $logDir ('backup-{0}.log' -f (Get-Date -Format 'yyyy-MM'))
    Add-Content -Path $logFile -Value $line
}

function ConvertTo-PlainText([securestring]$Secure) {
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

# Runs the Bitwarden CLI, returns stdout only, and throws if it fails.
function Invoke-Bw {
    # Windows PowerShell turns native stderr into error records; don't let
    # those abort the script before we can check the exit code.
    $ErrorActionPreference = 'Continue'
    $output = & $script:bw --nointeraction @args 2>&1
    $stdout = $output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
    $stderr = $output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
    if ($LASTEXITCODE -ne 0) {
        throw "bw $($args[0]) failed: $(($stderr + $stdout) -join ' ')"
    }
    $stdout
}

if (-not (Test-Path $configPath) -or -not (Test-Path $secretsPath)) {
    throw 'Backup is not set up yet. Run Setup-Backup.ps1 first.'
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$config  = Get-Content $configPath -Raw | ConvertFrom-Json
$secrets = Import-Clixml $secretsPath
$script:bw = $config.BwPath
$destinations = @($config.Destinations)

$exitCode = 0
try {
    Write-Log 'Backup started'

    $env:NODE_NO_WARNINGS = '1'
    $env:BW_CLIENTID      = ConvertTo-PlainText $secrets.ClientId
    $env:BW_CLIENTSECRET  = ConvertTo-PlainText $secrets.ClientSecret
    $env:BW_PASSWORD      = ConvertTo-PlainText $secrets.MasterPassword

    $status = (Invoke-Bw status) -join '' | ConvertFrom-Json
    if ($status.status -eq 'unauthenticated') {
        Write-Log 'Logging in with API key'
        Invoke-Bw login --apikey | Out-Null
    }

    $env:BW_SESSION = (Invoke-Bw unlock --passwordenv BW_PASSWORD --raw) -join ''
    Invoke-Bw sync | Out-Null

    $fileName = 'bitwarden-backup-{0}.json' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    New-Item -ItemType Directory -Force -Path $destinations[0] | Out-Null
    $primaryFile = Join-Path $destinations[0] $fileName

    $backupPassword = ConvertTo-PlainText $secrets.BackupPassword
    Invoke-Bw export --format encrypted_json --password $backupPassword --output $primaryFile | Out-Null
    $backupPassword = $null

    # Never leave a readable export lying around if something went wrong.
    $export = Get-Content $primaryFile -Raw | ConvertFrom-Json
    if (-not $export.encrypted -or -not $export.passwordProtected) {
        Remove-Item $primaryFile -Force
        throw 'Export was not password-protected, so it has been deleted.'
    }
    Write-Log "Saved $primaryFile"

    foreach ($dest in $destinations | Select-Object -Skip 1) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item $primaryFile -Destination $dest
        Write-Log "Copied to $dest"
    }

    foreach ($dest in $destinations) {
        Get-ChildItem -Path $dest -Filter 'bitwarden-backup-*.json' |
            Sort-Object Name -Descending |
            Select-Object -Skip $config.Keep |
            ForEach-Object {
                Remove-Item $_.FullName -Force
                Write-Log "Removed old backup $($_.Name)"
            }
    }

    Write-Log 'Backup finished'
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $exitCode = 1
}
finally {
    if ($env:BW_SESSION) {
        try { Invoke-Bw lock | Out-Null } catch { Write-Log "Could not lock vault: $($_.Exception.Message)" 'WARN' }
    }
    Remove-Item Env:BW_CLIENTID, Env:BW_CLIENTSECRET, Env:BW_PASSWORD, Env:BW_SESSION -ErrorAction SilentlyContinue
}

exit $exitCode
