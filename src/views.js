// Dependency-free HTML rendering via template literals.

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

const CSS = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0e14;color:#c9d1d9;font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
header h1{font-size:20px;margin:0 0 4px;letter-spacing:.5px}
header p{margin:0;color:#8b949e}
nav{margin:14px 0 28px;display:flex;gap:16px;flex-wrap:wrap}
.panel{background:#11161f;border:1px solid #21262d;border-radius:10px;padding:18px 20px;margin:16px 0}
.panel h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin:0 0 14px}
.ua-string{font-size:15px;word-break:break-all;background:#0b0e14;border:1px solid #21262d;border-radius:8px;padding:14px;color:#e6edf3}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:0}
.mono-break{word-break:break-all;max-width:520px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:#11161f;border:1px solid #21262d;border-radius:10px;padding:16px}
.card .n{font-size:26px;font-weight:700;color:#e6edf3}
.card .l{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.5px}
.tag.bot{background:#3d1d1d;color:#ff7b72;border:1px solid #5a2a2a}
.tag.human{background:#1d3d24;color:#7ee787;border:1px solid #2a5a34}
.bar{position:relative;background:#0b0e14;border-radius:5px;height:22px;overflow:hidden;border:1px solid #21262d}
.bar>span{position:absolute;inset:0 auto 0 0;background:linear-gradient(90deg,#1f6feb,#388bfd)}
.bar>b{position:relative;padding:0 8px;line-height:22px;font-weight:600;color:#e6edf3;mix-blend-mode:difference}
.spark{display:flex;gap:2px;align-items:flex-end;height:80px}
.spark div{flex:1;min-width:2px;background:#1f6feb;position:relative}
.spark div i{position:absolute;bottom:0;left:0;right:0;background:#ff7b72}
.muted{color:#8b949e}
footer{margin-top:40px;color:#8b949e;font-size:12px}
.hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
`;

function layout(title, body, { refresh = 0 } = {}) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
${refresh ? `<meta http-equiv="refresh" content="${refresh}">` : ''}
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body><div class="wrap">${body}</div></body>
</html>`;
}

const botTag = (isBot) =>
  isBot ? '<span class="tag bot">BOT</span>' : '<span class="tag human">HUMAN</span>';

export function renderIndex({ ua, parsed, headers, ipHashShown, trapLinks, baseUrl }) {
  const rows = [
    ['Classification', botTag(parsed.isBot) + (parsed.botName ? ` <span class="muted">${esc(parsed.botName)}</span>` : '')],
    ['Browser', esc(parsed.browser) + (parsed.browserVersion ? ` ${esc(parsed.browserVersion)}` : '')],
    ['Operating system', esc(parsed.os)],
    ['Device type', esc(parsed.device)],
    ['Accept-Language', esc(headers['accept-language'] || '—')],
    ['Referer', esc(headers['referer'] || '—')],
    ['Visitor id (hashed)', `<span class="muted">${esc(ipHashShown || '—')}</span>`],
  ];

  const body = `
<header>
  <h1>useragents.nichtregistriert.de</h1>
  <p>Your browser just told this server exactly what it is. It has been logged.</p>
</header>
<nav>
  <a href="/">home</a>
  <a href="/stats">statistics &rarr;</a>
  <a href="/api/stats">json api</a>
</nav>

<div class="panel">
  <h2>Your User-Agent</h2>
  <div class="ua-string">${esc(ua || '(no User-Agent header sent)')}</div>
</div>

<div class="panel">
  <h2>What we read from it</h2>
  <table><tbody>
    ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}
  </tbody></table>
</div>

<div class="panel">
  <h2>What happens with this data</h2>
  <p class="muted">
    Every request to this site stores a row: timestamp, the raw User-Agent string,
    requested path, referer, Accept-Language and a <em>salted, daily-rotating hash</em>
    of your IP address (never the address itself). No cookies, no tracking scripts,
    no third parties. The aggregated result is on the
    <a href="/stats">statistics page</a>.
  </p>
</div>

<footer>
  ${esc(baseUrl)} &middot; open crawler observatory &middot;
  <a href="/robots.txt">robots.txt</a> &middot; <a href="/sitemap.xml">sitemap.xml</a>
</footer>

<div class="hp" aria-hidden="true">
  ${trapLinks.map((h, i) => `<a href="${esc(h)}" rel="nofollow">catalogue entry ${i + 1}</a>`).join('')}
</div>`;
  return layout('useragents.nichtregistriert.de — your User-Agent, logged', body);
}

export function renderTrap({ depth, links, baseUrl }) {
  const body = `
<header><h1>index node ${depth}</h1><p class="muted">automatically generated catalogue page</p></header>
<div class="panel">
  <h2>sub-entries</h2>
  <ul>
    ${links.map((h, i) => `<li><a href="${esc(h)}" rel="nofollow">entry ${depth}.${i + 1}</a></li>`).join('')}
    ${links.length === 0 ? '<li class="muted">leaf node — no further entries</li>' : ''}
  </ul>
  <p class="muted"><a href="/">return to root</a></p>
</div>
<footer>${esc(baseUrl)} &middot; every hit here is recorded as a crawler visit</footer>`;
  return layout(`index node ${depth}`, body);
}

function barList(items, opts = {}) {
  const max = Math.max(1, ...items.map((i) => i.c));
  return `<table><tbody>${items
    .map(
      (i) => `<tr>
        <td class="mono-break">${esc(i.label ?? i.name ?? i.path)}${
        i.badge ? ` ${i.badge}` : ''
      }</td>
        <td style="width:55%"><div class="bar"><span style="width:${(
          (i.c / max) * 100
        ).toFixed(1)}%"></span><b>${i.c.toLocaleString('en')}${
        opts.showBots && i.bots ? ` · ${i.bots} bot` : ''
      }</b></div></td>
      </tr>`,
    )
    .join('')}</tbody></table>`;
}

export function renderStats(s, { baseUrl }) {
  const t = s.totals;
  const humanVisits = t.visits - t.bot_visits;
  const pct = t.visits ? ((t.bot_visits / t.visits) * 100).toFixed(1) : '0.0';

  const maxDay = Math.max(1, ...s.daily.map((d) => d.c));
  const spark = s.daily
    .map(
      (d) =>
        `<div style="height:${((d.c / maxDay) * 100).toFixed(1)}%" title="${esc(
          d.day,
        )}: ${d.c} (${d.bots || 0} bots)"><i style="height:${
          d.c ? ((d.bots / d.c) * 100).toFixed(1) : 0
        }%"></i></div>`,
    )
    .join('');

  const body = `
<header>
  <h1>statistics</h1>
  <p class="muted">generated ${esc(s.generatedAt)} · auto-refresh 30s</p>
</header>
<nav><a href="/">&larr; home</a><a href="/api/stats">json</a></nav>

<div class="cards">
  <div class="card"><div class="n">${t.visits.toLocaleString('en')}</div><div class="l">total requests</div></div>
  <div class="card"><div class="n">${t.uas.toLocaleString('en')}</div><div class="l">distinct user-agents</div></div>
  <div class="card"><div class="n">${t.bot_visits.toLocaleString('en')}</div><div class="l">bot requests (${pct}%)</div></div>
  <div class="card"><div class="n">${humanVisits.toLocaleString('en')}</div><div class="l">human requests</div></div>
  <div class="card"><div class="n">${t.bot_uas.toLocaleString('en')}</div><div class="l">distinct bots</div></div>
  <div class="card"><div class="n">${t.honeypot_hits.toLocaleString('en')}</div><div class="l">honeypot hits</div></div>
  <div class="card"><div class="n">${t.last24h.toLocaleString('en')}</div><div class="l">last 24 hours</div></div>
  <div class="card"><div class="n">${t.last7d.toLocaleString('en')}</div><div class="l">last 7 days</div></div>
</div>

<div class="panel">
  <h2>requests per day (last 30d, red = bots)</h2>
  ${s.daily.length ? `<div class="spark">${spark}</div>` : '<p class="muted">no data yet</p>'}
</div>

<div class="panel">
  <h2>most frequent user-agents</h2>
  <table>
    <thead><tr><th>user-agent</th><th>hits</th><th>class</th><th>browser / os</th><th>last seen</th></tr></thead>
    <tbody>
    ${s.topUserAgents
      .map(
        (u) => `<tr>
      <td class="mono-break">${esc(u.ua) || '<span class="muted">(empty)</span>'}</td>
      <td>${u.hits.toLocaleString('en')}</td>
      <td>${botTag(!!u.is_bot)}</td>
      <td class="muted">${esc(u.browser || '—')}${u.os ? ' / ' + esc(u.os) : ''}</td>
      <td class="muted">${esc(u.last_seen)}</td>
    </tr>`,
      )
      .join('')}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>top bots &amp; libraries</h2>
  ${s.topBots.length ? barList(s.topBots) : '<p class="muted">none yet</p>'}
</div>

<div class="panel">
  <h2>browsers</h2>
  ${barList(s.browsers)}
</div>

<div class="panel">
  <h2>operating systems</h2>
  ${barList(s.oses)}
</div>

<div class="panel">
  <h2>device types</h2>
  ${barList(s.devices)}
</div>

<div class="panel">
  <h2>most requested paths (probes included)</h2>
  ${barList(s.topPaths, { showBots: true })}
</div>

<div class="panel">
  <h2>newest user-agents seen</h2>
  <table>
    <thead><tr><th>first seen</th><th>class</th><th>user-agent</th></tr></thead>
    <tbody>
    ${s.newestUserAgents
      .map(
        (u) => `<tr>
      <td class="muted">${esc(u.first_seen)}</td>
      <td>${botTag(!!u.is_bot)}</td>
      <td class="mono-break">${esc(u.ua) || '<span class="muted">(empty)</span>'}</td>
    </tr>`,
      )
      .join('')}
    </tbody>
  </table>
</div>

<footer>${esc(baseUrl)} &middot; data collected since first request</footer>`;
  return layout('useragents.nichtregistriert.de — statistics', body, { refresh: 30 });
}

export function renderNotFound({ path, baseUrl }) {
  const body = `
<header><h1>404</h1><p class="muted">no such resource: ${esc(path)}</p></header>
<p>This request was still logged. <a href="/">go to the homepage</a> or see the
<a href="/stats">statistics</a>.</p>
<footer>${esc(baseUrl)}</footer>`;
  return layout('404', body);
}
