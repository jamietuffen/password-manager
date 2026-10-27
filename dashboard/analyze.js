'use strict';

// Works out the health of each login. Passwords are only used in memory here;
// the report it returns contains names, usernames and sites, never passwords.

const crypto = require('node:crypto');

const COMMON_WORDS = [
  'password', 'qwerty', 'letmein', 'welcome', 'admin', 'iloveyou', 'monkey',
  'dragon', 'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow',
  'superman', 'trustno1', 'changeme', 'secret', 'login', 'abc123', '123456', '111111',
];

const WEAK_BITS = 45;
const HIBP_CONCURRENCY = 8;

// Rough strength estimate in bits. Not as clever as a full cracker model, but
// it catches short passwords, repeats, sequences and "Word2024!" patterns.
function estimateBits(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  // Runs like "aaaa" or "abcd" or "1234" only count as one character.
  let effectiveLength = password.length ? 1 : 0;
  for (let i = 1; i < password.length; i++) {
    const step = password.charCodeAt(i) - password.charCodeAt(i - 1);
    if (Math.abs(step) > 1) effectiveLength++;
  }
  let bits = effectiveLength * Math.log2(pool || 1);

  const unLeet = password.toLowerCase()
    .replace(/[@4]/g, 'a').replace(/3/g, 'e').replace(/[1!]/g, 'i')
    .replace(/0/g, 'o').replace(/[$5]/g, 's');
  if (COMMON_WORDS.some((word) => unLeet.includes(word))) bits = Math.min(bits, 25);
  if (/^[A-Za-z][a-z]+\d{1,4}[^a-zA-Z0-9]{0,2}$/.test(password)) bits = Math.min(bits, 40);

  return Math.round(bits);
}

function strengthLabel(bits) {
  if (bits < 30) return 'Very weak';
  if (bits < WEAK_BITS) return 'Weak';
  if (bits < 60) return 'Fair';
  return 'Strong';
}

function parseUri(raw) {
  if (!raw) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url;
  } catch {
    return null;
  }
}

function summarise(item) {
  const raw = item.login.uris?.find((u) => parseUri(u.uri))?.uri ?? null;
  const url = parseUri(raw);
  return {
    id: item.id,
    name: item.name || '(no name)',
    username: item.login.username || '',
    domain: url ? url.hostname.replace(/^www\./, '') : '',
    href: url ? url.href : '',
    insecure: url ? url.protocol === 'http:' : false,
  };
}

// Have I Been Pwned "range" API: only the first 5 characters of the SHA-1
// hash leave this PC, so the service never learns the password.
async function checkBreaches(passwords) {
  const counts = new Map();
  const queue = [...passwords];
  const ranges = new Map();

  async function lookup(password) {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    if (!ranges.has(prefix)) {
      ranges.set(prefix, fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'personal-vault-health-dashboard' },
      }).then((res) => {
        if (!res.ok) throw new Error(`Have I Been Pwned returned ${res.status}`);
        return res.text();
      }));
    }
    const body = await ranges.get(prefix);
    for (const line of body.split('\n')) {
      const [hashSuffix, count] = line.trim().split(':');
      if (hashSuffix === suffix) return Number(count);
    }
    return 0;
  }

  async function worker() {
    while (queue.length) {
      const password = queue.shift();
      counts.set(password, await lookup(password));
    }
  }

  await Promise.all(Array.from({ length: HIBP_CONCURRENCY }, worker));
  return counts;
}

// 2fa.directory lists sites that support authenticator-app codes.
async function loadTwoFactorSites() {
  const res = await fetch('https://api.2fa.directory/v3/totp.json');
  if (!res.ok) throw new Error(`2fa.directory returned ${res.status}`);
  const sites = new Map();
  for (const [name, info] of await res.json()) {
    for (const domain of [info.domain, ...(info['additional-domains'] ?? [])]) {
      sites.set(domain, { name, documentation: info.documentation || info.url || '' });
    }
  }
  return sites;
}

function findTwoFactorSite(domain, sites) {
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const site = sites.get(parts.slice(i).join('.'));
    if (site) return site;
  }
  return null;
}

async function analyse(items) {
  const logins = items.filter((item) => item.type === 1 && item.login);
  const typeNames = { 1: 'logins', 2: 'secure notes', 3: 'cards', 4: 'identities', 5: 'SSH keys' };
  const typeCounts = {};
  for (const item of items) {
    const name = typeNames[item.type] || 'other items';
    typeCounts[name] = (typeCounts[name] || 0) + 1;
  }

  const report = {
    generatedAt: new Date().toISOString(),
    total: logins.length,
    allItems: items.length,
    typeCounts,
    breached: [],
    reused: [],
    weak: [],
    twoFactor: [],
    insecure: [],
    empty: [],
    warnings: [],
  };

  const byPassword = new Map();
  for (const item of logins) {
    const summary = summarise(item);
    const password = item.login.password || '';
    if (!password) {
      report.empty.push(summary);
      continue;
    }
    if (!byPassword.has(password)) byPassword.set(password, []);
    byPassword.get(password).push(summary);

    const bits = estimateBits(password);
    if (bits < WEAK_BITS) report.weak.push({ ...summary, strength: strengthLabel(bits), bits });
    if (summary.insecure) report.insecure.push(summary);
  }

  for (const group of byPassword.values()) {
    if (group.length > 1) report.reused.push(group);
  }
  report.reused.sort((a, b) => b.length - a.length);
  report.weak.sort((a, b) => a.bits - b.bits);

  try {
    const breachCounts = await checkBreaches(byPassword.keys());
    for (const [password, count] of breachCounts) {
      if (count > 0) {
        for (const summary of byPassword.get(password)) report.breached.push({ ...summary, count });
      }
    }
    report.breached.sort((a, b) => b.count - a.count);
  } catch (err) {
    report.warnings.push(`Breach check skipped: ${err.message}`);
  }

  try {
    const sites = await loadTwoFactorSites();
    for (const item of logins) {
      if (item.login.totp) continue;
      const summary = summarise(item);
      const site = summary.domain && findTwoFactorSite(summary.domain, sites);
      if (site) report.twoFactor.push({ ...summary, documentation: site.documentation });
    }
    report.twoFactor.sort((a, b) => a.name.localeCompare(b.name));
  } catch (err) {
    report.warnings.push(`2FA check skipped: ${err.message}`);
  }

  const flagged = new Set([
    ...report.breached, ...report.reused.flat(), ...report.weak, ...report.empty,
  ].map((s) => s.id));
  report.healthy = report.total - flagged.size;

  return report;
}

module.exports = { analyse, estimateBits, strengthLabel };
