# Bitwarden automatic backups

A daily, password-protected backup of your Bitwarden vault, saved to OneDrive
(or any folders you choose) by Windows Task Scheduler.

## Setup (once)

1. Install the Bitwarden CLI: `npm install -g @bitwarden/cli`
2. In the Bitwarden web vault go to **Settings > Security > Keys > View API key**
   and keep the `client_id` and `client_secret` handy.
3. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\backup\Setup-Backup.ps1
   ```

   Options: `-Destination "$env:OneDrive\Bitwarden Backups", 'E:\Backups'`,
   `-Keep 60`, `-Time '12:30'`, or `-Uninstall`.

## Restoring

1. Log in to the Bitwarden web vault (a brand-new account works too).
2. **Tools > Import data**, format **Bitwarden (json)**.
3. Choose the newest `bitwarden-backup-*.json` and enter your **backup file password**.

Test a restore into a spare free account once, so you know it works before you need it.

## What's stored where

| Item | Location |
|---|---|
| Backups | `OneDrive\Bitwarden Backups` by default |
| Settings | `%LOCALAPPDATA%\BitwardenBackup\config.json` |
| Credentials (DPAPI-encrypted) | `%LOCALAPPDATA%\BitwardenBackup\secrets.xml` |
| Logs | `%LOCALAPPDATA%\BitwardenBackup\logs\` |

## Good to know

- The stored credentials can only be decrypted by your Windows account on this
  PC. Keep that account password-protected (BitLocker is a bonus).
- File **attachments** aren't included in Bitwarden exports, only vault items.
- If a backup fails, check the log or the **Last Run Result** of the task in
  Task Scheduler.
