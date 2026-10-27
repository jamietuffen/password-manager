# Vault health dashboard

Checks your Bitwarden logins for:

- **Breached** passwords (via Have I Been Pwned)
- **Reused** passwords
- **Weak** passwords
- Sites that offer **two-step login** where no authenticator code is saved in Bitwarden
- Logins saved with an insecure **http://** address, or with **no password**

The header also shows how many items are in your vault, broken down by type.

## Filtering

- **Search** by name, username or website.
- **Click a tile** to show just that category; click it again to show everything.
- **Ignore** a row (or **Already set up** for 2FA you have in another
  authenticator app) to hide it. Tick **Show ignored** to see them again and **Undo**.
  Ignored rows don't count against your health score, and are remembered between runs.

## Running it

Double-click **`Vault Health.cmd`** (or run `node server.js`), enter your
master password, and the report opens in your browser.

Needs the Bitwarden CLI logged in, which `backup/Setup-Backup.ps1` already did.

## How it keeps things safe

- Your master password is typed into the terminal and passed to the CLI in memory only.
- The vault is locked again as soon as your logins have been read.
- The browser page never receives any passwords, only names, usernames, sites and results.
- The page is served on `127.0.0.1` (this PC only) at a random, one-off address,
  and the dashboard shuts itself down after 30 minutes.
- Breach checks use Have I Been Pwned's k-anonymity API: only the first 5
  characters of each password's SHA-1 hash are sent.
- The only thing written to disk is your ignore list
  (`%LOCALAPPDATA%\VaultHealth\dismissed.json`), which holds item IDs and categories, never passwords.

## Files

| File | Does |
|---|---|
| `server.js` | Unlocks, reads, locks, serves the page |
| `analyze.js` | Strength, reuse, breach and 2FA checks |
| `page.js` | Builds the HTML report |
