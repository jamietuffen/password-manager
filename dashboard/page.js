'use strict';

// Renders the report as a single self-contained HTML page. A small inline
// script (allowed by a per-run CSP nonce) handles search, filtering and
// ignoring rows.

const CATEGORIES = [
  { id: 'breached', title: 'Breached passwords', tile: 'Breached', tone: 'bad', health: true,
    intro: 'These passwords have appeared in data breaches, so attackers try them first. Change these before anything else.' },
  { id: 'reused', title: 'Reused passwords', tile: 'Reused', tone: 'warn', health: true,
    intro: 'If one of these sites is hacked, every login sharing the password is exposed. Give each one its own generated password.' },
  { id: 'weak', title: 'Weak passwords', tile: 'Weak', tone: 'warn', health: true,
    intro: 'Short or predictable passwords. Replace them using Bitwarden\'s password generator (aim for 16+ characters).' },
  { id: 'twofactor', title: 'Sites that support two-step login', tile: '2FA available', tone: 'info', health: false,
    intro: 'These sites offer authenticator codes but none is saved in Bitwarden. Already using Google Authenticator for one? Click "Already set up" and it won\'t be shown again.' },
  { id: 'insecure', title: 'Saved with an http:// address', tile: 'http:// address', tone: 'info', health: false,
    intro: 'The saved web address isn\'t encrypted. Edit the item and change it to https:// if the site supports it.' },
  { id: 'empty', title: 'Logins with no password', tile: 'No password', tone: 'info', health: true,
    intro: 'Fine if they use "Sign in with Google" or similar (click Ignore); otherwise add the password or delete the item.' },
];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function externalLink(href, text) {
  if (!/^https?:\/\//i.test(href)) return esc(text);
  return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>`;
}

function row(category, item, vaultUrl, dismissed, extraCell = '') {
  const key = `${category.id}:${item.id}`;
  const isDismissed = dismissed.has(key);
  const label = category.id === 'twofactor' ? 'Already set up' : 'Ignore';
  const edit = `${vaultUrl}/#/vault?itemId=${encodeURIComponent(item.id)}`;
  const search = `${item.name} ${item.username} ${item.domain}`.toLowerCase();
  return `
    <tr class="row${isDismissed ? ' dismissed' : ''}" data-key="${esc(key)}" data-cat="${category.id}"
        data-id="${esc(item.id)}" data-health="${category.health ? 1 : 0}" data-search="${esc(search)}">
      <td><strong>${esc(item.name)}</strong><span class="sub">${esc(item.username)}</span></td>
      <td>${item.href ? externalLink(item.href, item.domain) : '<span class="muted">No website</span>'}</td>
      ${extraCell}
      <td class="actions">
        ${externalLink(edit, 'Edit in Bitwarden')}
        <button type="button" class="dismiss" data-label="${label}">${isDismissed ? 'Undo' : label}</button>
      </td>
    </tr>`;
}

function table(headers, rows) {
  return `<div class="table-wrap"><table>
    <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('')}</tbody></table></div>`;
}

function sectionBody(category, report, vaultUrl, dismissed) {
  const r = (item, extra) => row(category, item, vaultUrl, dismissed, extra);
  switch (category.id) {
    case 'breached':
      return table(['Login', 'Website', 'Seen in breaches', ''], report.breached.map((item) =>
        r(item, `<td class="num-cell">${item.count.toLocaleString('en-GB')} times</td>`)));
    case 'reused':
      return report.reused.map((group, i) => `
        <div class="group">
          <h3>Password ${i + 1} <span class="muted">shared by ${group.length} logins</span></h3>
          ${table(['Login', 'Website', ''], group.map((item) => r(item)))}
        </div>`).join('');
    case 'weak':
      return table(['Login', 'Website', 'Strength', ''], report.weak.map((item) =>
        r(item, `<td><span class="pill ${item.bits < 30 ? 'bad' : 'warn'}">${esc(item.strength)}</span></td>`)));
    case 'twofactor':
      return table(['Login', 'Website', 'Guide', ''], report.twoFactor.map((item) =>
        r(item, `<td>${item.documentation ? externalLink(item.documentation, 'How to set up') : ''}</td>`)));
    default:
      return table(['Login', 'Website', ''], report[category.id].map((item) => r(item)));
  }
}

function renderPage(report, vaultUrl, dismissed, nonce) {
  const generated = new Date(report.generatedAt).toLocaleString('en-GB');

  const tiles = CATEGORIES.map((c) => `
    <button type="button" class="tile ${c.tone}" data-filter="${c.id}" aria-pressed="false">
      <span class="num">0</span><span class="label">${esc(c.tile)}</span>
    </button>`).join('');

  const sections = CATEGORIES.map((c) => `
    <details class="section ${c.tone}" data-section="${c.id}" open>
      <summary><span class="badge">0</span>${esc(c.title)}</summary>
      <p class="intro">${c.intro}</p>
      ${sectionBody(c, report, vaultUrl, dismissed)}
      <p class="none">✓ Nothing to show here.</p>
    </details>`).join('');

  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Vault Health</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --text: #1b1f24; --muted: #667085; --border: #e4e7ec;
    --bad: #c0362c; --bad-bg: #fdecea; --warn: #b54708; --warn-bg: #fef4e6;
    --info: #175cd3; --info-bg: #eaf2ff; --ok: #067647; --ok-bg: #e7f6ee;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1216; --card: #171b21; --text: #e6e8eb; --muted: #98a2b3; --border: #2a3039;
      --bad: #f97066; --bad-bg: #3a1714; --warn: #fdb022; --warn-bg: #3a2a0c;
      --info: #84adff; --info-bg: #14233f; --ok: #47cd89; --ok-bg: #0f2e1f;
    }
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }
  a { color: var(--info); }
  header { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; margin-bottom: 24px; }
  .score { --pct: 100; width: 120px; height: 120px; border-radius: 50%; display: grid; place-items: center;
    background: conic-gradient(var(--ok) calc(var(--pct) * 3.6deg), var(--border) 0); flex: none; }
  .score span { width: 96px; height: 96px; border-radius: 50%; background: var(--bg);
    display: grid; place-items: center; font-size: 28px; font-weight: 700; }
  h1 { margin: 0 0 4px; font-size: 28px; }
  .muted, .sub { color: var(--muted); }
  .sub { display: block; font-size: 13px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .tile { background: var(--card); border: 2px solid var(--border); border-radius: 12px; padding: 14px 16px;
    color: var(--text); display: flex; flex-direction: column; align-items: flex-start; font: inherit; cursor: pointer; text-align: left; }
  .tile:hover { border-color: var(--muted); }
  .tile[aria-pressed="true"] { border-color: var(--info); box-shadow: 0 0 0 3px var(--info-bg); }
  .tile .num { font-size: 30px; font-weight: 700; line-height: 1.1; }
  .tile.bad .num { color: var(--bad); } .tile.warn .num { color: var(--warn); } .tile.info .num { color: var(--info); }
  .tile.zero .num { color: var(--ok); }
  .toolbar { position: sticky; top: 0; z-index: 1; background: var(--bg); padding: 12px 0; margin-bottom: 8px;
    display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
  .toolbar input[type="search"] { flex: 1 1 260px; padding: 10px 14px; font: inherit; color: var(--text);
    background: var(--card); border: 1px solid var(--border); border-radius: 8px; }
  .toolbar label { display: flex; gap: 6px; align-items: center; color: var(--muted); cursor: pointer; }
  .toolbar .clear { font: inherit; background: none; border: none; color: var(--info); cursor: pointer; padding: 0; }
  .warning { background: var(--warn-bg); color: var(--warn); padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; }
  .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 4px 20px; margin-bottom: 16px; }
  summary { cursor: pointer; font-size: 18px; font-weight: 600; padding: 14px 0; display: flex; align-items: center; gap: 12px; }
  .badge { min-width: 32px; padding: 2px 10px; border-radius: 999px; text-align: center; font-size: 14px; }
  .bad .badge { background: var(--bad-bg); color: var(--bad); }
  .warn .badge { background: var(--warn-bg); color: var(--warn); }
  .info .badge { background: var(--info-bg); color: var(--info); }
  .section.zero .badge { background: var(--ok-bg); color: var(--ok); }
  .intro { margin-top: 0; color: var(--muted); }
  .none { color: var(--ok); }
  h3 { font-size: 15px; margin: 20px 0 8px; }
  .table-wrap { overflow-x: auto; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 8px; border-top: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 13px; color: var(--muted); font-weight: 500; border-top: none; }
  tr.dismissed td { opacity: 0.45; }
  tr.dismissed td.actions { opacity: 1; }
  td.actions { white-space: nowrap; text-align: right; }
  td.actions a { margin-right: 12px; }
  .dismiss { font: inherit; font-size: 13px; padding: 4px 10px; border-radius: 6px; cursor: pointer;
    background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .dismiss:hover { color: var(--text); border-color: var(--muted); }
  td.num-cell { font-variant-numeric: tabular-nums; color: var(--bad); font-weight: 600; white-space: nowrap; }
  .pill { padding: 2px 8px; border-radius: 999px; font-size: 13px; white-space: nowrap; }
  .pill.bad { background: var(--bad-bg); color: var(--bad); } .pill.warn { background: var(--warn-bg); color: var(--warn); }
  footer { color: var(--muted); font-size: 13px; margin-top: 32px; }
</style>
</head>
<body data-total="${report.total}">
<main>
  <header>
    <div class="score" id="score"><span id="score-pct">–</span></div>
    <div>
      <h1>Vault health</h1>
      <div class="muted"><span id="healthy">–</span> of ${report.total} logins have no outstanding problems · checked ${esc(generated)}</div>
      <div class="muted">${report.allItems} items in your vault: ${Object.entries(report.typeCounts).map(([name, n]) => `${n} ${esc(name)}`).join(' · ')}</div>
    </div>
  </header>

  ${report.warnings.map((w) => `<div class="warning">${esc(w)}</div>`).join('')}

  <nav class="tiles">${tiles}</nav>

  <div class="toolbar">
    <input type="search" id="search" placeholder="Search by name, username or website…" autocomplete="off">
    <label><input type="checkbox" id="show-ignored"> Show ignored (<span id="ignored-count">0</span>)</label>
    <button type="button" class="clear" id="clear" hidden>Clear filters</button>
  </div>

  ${sections}

  <footer>
    Generated on this PC only. No passwords were sent to this page or saved to disk; the only thing saved is
    the list of items you've ignored. Breach checks send just the first 5 characters of each password's
    SHA-1 hash to Have I Been Pwned. Close the terminal window (or press Ctrl+C) to shut the dashboard down.
  </footer>
</main>

<script nonce="${nonce}">
(() => {
  const rows = [...document.querySelectorAll('tr.row')];
  const sections = [...document.querySelectorAll('details.section')];
  const tiles = [...document.querySelectorAll('.tile')];
  const search = document.getElementById('search');
  const showIgnored = document.getElementById('show-ignored');
  const clear = document.getElementById('clear');
  const total = Number(document.body.dataset.total);
  let active = null;

  function apply() {
    const q = search.value.trim().toLowerCase();
    for (const r of rows) {
      const ignored = r.classList.contains('dismissed');
      r.hidden = (q && !r.dataset.search.includes(q)) || (ignored && !showIgnored.checked);
    }

    for (const s of sections) {
      const cat = s.dataset.section;
      const mine = rows.filter((r) => r.dataset.cat === cat);
      const visible = mine.filter((r) => !r.hidden);
      const outstanding = visible.filter((r) => !r.classList.contains('dismissed')).length;
      s.hidden = active !== null && active !== cat;
      if (active === cat) s.open = true;
      s.classList.toggle('zero', outstanding === 0);
      s.querySelector('.badge').textContent = outstanding;
      s.querySelector('.none').hidden = visible.length > 0;
      for (const t of s.querySelectorAll('table')) t.closest('.table-wrap').hidden = !t.querySelector('tr.row:not([hidden])');
      for (const g of s.querySelectorAll('.group')) g.hidden = !g.querySelector('tr.row:not([hidden])');

      const tile = tiles.find((t) => t.dataset.filter === cat);
      tile.querySelector('.num').textContent = outstanding;
      tile.classList.toggle('zero', outstanding === 0);
      tile.setAttribute('aria-pressed', String(active === cat));
    }

    const flagged = new Set(rows
      .filter((r) => r.dataset.health === '1' && !r.classList.contains('dismissed'))
      .map((r) => r.dataset.id));
    const healthy = total - flagged.size;
    const pct = total ? Math.round((healthy / total) * 100) : 100;
    document.getElementById('score').style.setProperty('--pct', pct);
    document.getElementById('score-pct').textContent = pct + '%';
    document.getElementById('healthy').textContent = healthy;
    document.getElementById('ignored-count').textContent = rows.filter((r) => r.classList.contains('dismissed')).length;
    clear.hidden = !q && active === null;
  }

  for (const t of tiles) {
    t.addEventListener('click', () => {
      active = active === t.dataset.filter ? null : t.dataset.filter;
      apply();
    });
  }
  search.addEventListener('input', apply);
  showIgnored.addEventListener('change', apply);
  clear.addEventListener('click', () => { search.value = ''; active = null; apply(); search.focus(); });

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('button.dismiss');
    if (!btn) return;
    const row = btn.closest('tr');
    const dismissed = !row.classList.contains('dismissed');
    btn.disabled = true;
    try {
      const res = await fetch(location.pathname + '/dismiss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: row.dataset.key, dismissed }),
      });
      if (!res.ok) throw new Error(res.status);
      row.classList.toggle('dismissed', dismissed);
      btn.textContent = dismissed ? 'Undo' : btn.dataset.label;
    } catch {
      alert('Could not save that change. Is the dashboard still running?');
    } finally {
      btn.disabled = false;
      apply();
    }
  });

  apply();
})();
</script>
</body>
</html>`;
}

module.exports = { renderPage };
