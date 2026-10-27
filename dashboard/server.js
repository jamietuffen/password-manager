#!/usr/bin/env node
'use strict';

// Vault health dashboard.
// Unlocks Bitwarden with your master password, reads your logins, locks the
// vault again straight away, then serves the report on this PC only.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const { analyse } = require('./analyze');
const { renderPage } = require('./page');

const BW_JS = path.join(process.env.APPDATA || '', 'npm', 'node_modules', '@bitwarden', 'cli', 'build', 'bw.js');
const AUTO_CLOSE_MINUTES = 30;

// Rows you've ignored, stored as "category:itemId" only (never passwords).
const STATE_DIR = path.join(process.env.LOCALAPPDATA || require('node:os').homedir(), 'VaultHealth');
const DISMISSED_FILE = path.join(STATE_DIR, 'dismissed.json');
const DISMISS_KEY = /^(breached|reused|weak|twofactor|insecure|empty):[0-9a-f-]{36}$/i;

function loadDismissed() {
  try {
    return new Set(JSON.parse(fs.readFileSync(DISMISSED_FILE, 'utf8')));
  } catch {
    return new Set();
  }
}

function saveDismissed(dismissed) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(DISMISSED_FILE, JSON.stringify([...dismissed].sort(), null, 2));
}

function readJsonBody(req, limit = 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > limit) reject(new Error('Body too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

// Runs the Bitwarden CLI with node directly, so no shell is involved.
function bw(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BW_JS, '--nointeraction', ...args], {
      env: { ...process.env, NODE_NO_WARNINGS: '1', ...env },
      windowsHide: true,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve(out.trim());
      else reject(new Error(err.trim() || out.trim() || `bw ${args[0]} exited with code ${code}`));
    });
  });
}

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let muted = false;
    rl._writeToOutput = (text) => { if (!muted) rl.output.write(text); };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    muted = true;
  });
}

function openBrowser(url) {
  spawn('rundll32', ['url.dll,FileProtocolHandler', url], { detached: true, stdio: 'ignore' }).unref();
}

async function readVault() {
  const status = JSON.parse(await bw(['status']));
  if (status.status === 'unauthenticated') {
    throw new Error('The Bitwarden CLI is not logged in. Run backup\\Setup-Backup.ps1 first.');
  }
  const vaultUrl = (status.serverUrl || 'https://vault.bitwarden.com').replace(/\/$/, '');

  const password = await askHidden('Bitwarden master password: ');
  try {
    const session = await bw(['unlock', '--passwordenv', 'BW_DASHBOARD_PASSWORD', '--raw'],
      { BW_DASHBOARD_PASSWORD: password });
    console.log('Unlocked. Syncing...');
    await bw(['sync'], { BW_SESSION: session });
    const items = JSON.parse(await bw(['list', 'items'], { BW_SESSION: session }));
    return { items, vaultUrl };
  } finally {
    await bw(['lock']).catch(() => {});
    console.log('Vault locked again.');
  }
}

// The token in the URL means other programs on this PC can't just browse to
// the port and read the report.
function createServer({ report, vaultUrl, dismissed, token, save = saveDismissed }) {
  return http.createServer(async (req, res) => {
    const send = (status, type, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers });
      res.end(body);
    };

    if (req.method === 'GET' && req.url === `/${token}`) {
      const nonce = crypto.randomBytes(16).toString('base64');
      send(200, 'text/html; charset=utf-8', renderPage(report, vaultUrl, dismissed, nonce), {
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'`,
      });
      return;
    }

    if (req.method === 'POST' && req.url === `/${token}/dismiss`) {
      if (!String(req.headers['content-type']).startsWith('application/json')) {
        send(415, 'text/plain', 'Expected JSON');
        return;
      }
      try {
        const { key, dismissed: isDismissed } = await readJsonBody(req);
        if (!DISMISS_KEY.test(key)) throw new Error('Bad key');
        if (isDismissed) dismissed.add(key);
        else dismissed.delete(key);
        save(dismissed);
        send(204, 'text/plain', '');
      } catch {
        send(400, 'text/plain', 'Bad request');
      }
      return;
    }

    send(404, 'text/plain', 'Not found');
  });
}

async function main() {
  if (!fs.existsSync(BW_JS)) {
    throw new Error('Bitwarden CLI not found. Install it with: npm install -g @bitwarden/cli');
  }

  const { items, vaultUrl } = await readVault();
  console.log(`Checking ${items.length} items (breaches and 2FA lookups can take a moment)...`);
  const report = await analyse(items);
  const token = crypto.randomBytes(24).toString('base64url');
  const server = createServer({ report, vaultUrl, dismissed: loadDismissed(), token });

  server.listen(0, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${server.address().port}/${token}`;
    console.log(`\nDashboard ready: ${url}`);
    console.log(`It closes automatically in ${AUTO_CLOSE_MINUTES} minutes, or press Ctrl+C.\n`);
    openBrowser(url);
  });

  setTimeout(() => {
    console.log('Dashboard closed.');
    process.exit(0);
  }, AUTO_CLOSE_MINUTES * 60 * 1000);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`\nError: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { createServer };
