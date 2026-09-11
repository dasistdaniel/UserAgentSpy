// Dependency-free HTML rendering via template literals.

import { SPOOF_THRESHOLD, explainCodes } from './fingerprint.js';

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
.filters{display:flex;gap:10px;align-items:center;margin:-10px 0 22px;flex-wrap:wrap}
.filters a{padding:2px 12px;border:1px solid #21262d;border-radius:999px;color:#8b949e}
.filters a.on{background:#1f6feb;border-color:#1f6feb;color:#fff}
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
<link rel="alternate" type="application/atom+xml" title="newest user-agents" href="/feed.xml">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body><div class="wrap">${body}</div></body>
</html>`;
}

const botTag = (isBot) =>
  isBot ? '<span class="tag bot">BOT</span>' : '<span class="tag human">HUMAN</span>';

// A user-agent string. Only bots get an individually-identifiable public detail
// page (/stats/ua/<hash>) — human entries render as plain text, matching the
// data-minimization stance explained on /datenschutz.
const uaCell = (hash, ua, isBot) => {
  const text = esc(ua) || '<span class="muted">(empty)</span>';
  return isBot
    ? `<a class="mono-break" href="/stats/ua/${esc(hash)}">${text}</a>`
    : `<span class="mono-break">${text}</span>`;
};

// Canonical public name — shown in every footer regardless of the BASE_URL the
// container happens to run with (LAN IP during testing, etc.).
const SITE = 'useragents.nichtregistriert.de';
const SITE_LINK = `<a href="https://${SITE}">${SITE}</a>`;

const STATUS_TEXT = {
  200: 'OK',
  204: 'No Content',
  400: 'Bad Request',
  404: 'Not Found',
  405: 'Method Not Allowed',
};

function fingerprintVerdict(parsed, fp) {
  if (!fp || !fp.claimsBrowser) {
    return '<span class="muted">n/a — not claiming a mainstream browser</span>';
  }
  if (fp.spoofScore === 0) {
    return `<span class="tag human">CONSISTENT</span> headers match ${esc(parsed.browser)}`;
  }
  const reasons = explainCodes(fp.codes.join(','))
    .map((r) => `<li>${esc(r)}</li>`)
    .join('');
  return `<span class="tag bot">MISMATCH</span> score ${fp.spoofScore}
    <ul class="muted" style="margin:6px 0 0;padding-left:18px">${reasons}</ul>`;
}

export function renderIndex({ ua, parsed, fp, headers, ipHashShown, trapLinks, dnt }) {
  const fpRows = [
    ['HTTP version', esc(fp.httpVersion)],
    ['Accept', `<span class="mono-break">${esc(fp.accept || '—')}</span>`],
    ['Accept-Encoding', esc(fp.acceptEncoding || '—')],
    ['Sec-Fetch (site/mode/dest/user)', esc(fp.secFetch || '—')],
    ['Sec-CH-UA', `<span class="mono-break">${esc(fp.secChUa || '—')}</span>`],
    ['Consistency', fingerprintVerdict(parsed, fp)],
  ];

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
  <h2>Header fingerprint</h2>
  <p class="muted">Beyond the UA string, real browsers send a predictable set of
  headers. Here is what yours sent, and whether it matches the browser it claims.</p>
  <table><tbody>
    ${fpRows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}
  </tbody></table>
</div>

<div class="panel">
  <h2>What happens with this data</h2>
  <p class="muted">
    ${
      dnt
        ? `This visit was <strong>not</strong> written to the database — either your browser
           sent <code>DNT: 1</code> / <code>Sec-GPC: 1</code>, or a self-exclusion is active.
           Everything above was still computed just to show it back to you; none of it was
           stored.`
        : `Every request to this site stores a row: timestamp, the raw User-Agent string,
           requested path, the <em>origin only</em> of the referer (never its full path or
           query string), Accept-Language, and a <em>salted, daily-rotating hash</em> of your
           IP address (never the address itself). No cookies are set for ordinary visitors, no
           tracking scripts, no third parties. Individual, timestamped request histories are
           published only for bots and crawlers — human visitors appear only in aggregate on the
           <a href="/stats">statistics page</a>. Send <code>DNT: 1</code> or
           <code>Sec-GPC: 1</code> to opt out of storage entirely.`
    }
    Full details: <a href="/datenschutz">privacy policy</a>.
  </p>
</div>

<footer>
  ${SITE_LINK} &middot; open crawler observatory &middot;
  <a href="/robots.txt">robots.txt</a> &middot; <a href="/sitemap.xml">sitemap.xml</a>
  &middot; <a href="/feed.xml">feed</a> &middot; <a href="/llms.txt">llms.txt</a>
  &middot; <a href="/datenschutz">privacy</a>
</footer>

<div class="hp" aria-hidden="true">
  ${trapLinks.map((h, i) => `<a href="${esc(h)}" rel="nofollow">catalogue entry ${i + 1}</a>`).join('')}
</div>`;
  return layout('useragents.nichtregistriert.de — your User-Agent, logged', body);
}

export function renderTrap({ depth, links }) {
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
<footer>${SITE_LINK} &middot; every hit here is recorded as a crawler visit &middot;
  <a href="/datenschutz">privacy</a></footer>`;
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

export function renderStats(s) {
  const t = s.totals;
  const humanVisits = t.visits - t.bot_visits;
  const pct = t.visits ? ((t.bot_visits / t.visits) * 100).toFixed(1) : '0.0';
  const f = s.filter || 'all';
  const filterLink = (key, label, href) =>
    `<a href="${href}"${f === key ? ' class="on"' : ''}>${label}</a>`;

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
  <p class="muted">generated ${esc(s.generatedAt)} · auto-refresh 30s${
    f === 'all' ? '' : ` · showing <strong>${f}</strong> only`
  }</p>
</header>
<nav><a href="/">&larr; home</a><a href="/api/stats${
  f === 'all' ? '' : '?filter=' + f
}">json</a></nav>
<div class="filters">
  <span class="muted">filter:</span>
  ${filterLink('all', 'all', '/stats')}
  ${filterLink('humans', 'humans', '/stats?filter=humans')}
  ${filterLink('bots', 'bots', '/stats?filter=bots')}
</div>

<div class="cards">
  <div class="card"><div class="n">${t.visits.toLocaleString('en')}</div><div class="l">total requests</div></div>
  <div class="card"><div class="n">${t.uas.toLocaleString('en')}</div><div class="l">distinct user-agents</div></div>
  <div class="card"><div class="n">${t.bot_visits.toLocaleString('en')}</div><div class="l">bot requests (${pct}%)</div></div>
  <div class="card"><div class="n">${humanVisits.toLocaleString('en')}</div><div class="l">human requests</div></div>
  <div class="card"><div class="n">${t.bot_uas.toLocaleString('en')}</div><div class="l">distinct bots</div></div>
  <div class="card"><div class="n">${t.honeypot_hits.toLocaleString('en')}</div><div class="l">honeypot hits</div></div>
  ${
    t.decoy_hits
      ? `<div class="card"><div class="n">${t.decoy_hits.toLocaleString('en')}</div><div class="l">decoy endpoint hits</div></div>`
      : ''
  }
  <div class="card"><div class="n">${t.last24h.toLocaleString('en')}</div><div class="l">last 24 hours</div></div>
  <div class="card"><div class="n">${t.last7d.toLocaleString('en')}</div><div class="l">last 7 days</div></div>
  <div class="card"><div class="n">${(t.spoofed_visits || 0).toLocaleString('en')}</div><div class="l">spoofed-browser hits</div></div>
</div>

<div class="panel">
  <h2>requests per day (last 30d${f === 'all' ? ', red = bots' : ''})</h2>
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
      <td>${uaCell(u.ua_hash, u.ua, !!u.is_bot)}</td>
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

${
  f === 'humans'
    ? ''
    : `<div class="panel">
  <h2>top bots &amp; libraries</h2>
  ${s.topBots.length ? barList(s.topBots) : '<p class="muted">none yet</p>'}
</div>`
}

${
  f === 'bots'
    ? ''
    : `<div class="panel">
  <h2>header fingerprint</h2>
  <p class="muted">
    <strong>${(t.spoofed_visits || 0).toLocaleString('en')}</strong> hits from
    <strong>${(t.spoofed_uas || 0).toLocaleString('en')}</strong> user-agents claim a
    real browser but their request headers don't match one (spoof score &ge;
    ${SPOOF_THRESHOLD}).${
      s.clientHints && s.clientHints.chromium_visits
        ? ` Client Hints (Sec-CH-UA) seen on ${(
            s.clientHints.with_hints || 0
          ).toLocaleString('en')} of ${s.clientHints.chromium_visits.toLocaleString(
            'en',
          )} Chromium visits.`
        : ''
    }
  </p>
  ${
    s.spoofedUserAgents && s.spoofedUserAgents.length
      ? `<table>
    <thead><tr><th>user-agent</th><th>hits</th><th>score</th><th>failed checks</th></tr></thead>
    <tbody>
    ${s.spoofedUserAgents
      .map(
        (u) => `<tr>
      <td>${uaCell(u.ua_hash, u.ua, false)}</td>
      <td>${u.c.toLocaleString('en')}</td>
      <td>${u.score}</td>
      <td class="muted">${explainCodes(u.reasons).map(esc).join('; ')}</td>
    </tr>`,
      )
      .join('')}
    </tbody>
  </table>`
      : '<p class="muted">none yet — every browser-claiming visit passed the header check</p>'
  }
</div>`
}

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
  <h2>response status codes</h2>
  ${barList(
    (s.statusCodes || []).map((r) => ({
      label: `${r.status} · ${STATUS_TEXT[r.status] || 'other'}`,
      c: r.c,
      bots: r.bots,
    })),
    { showBots: true },
  )}
</div>

${
  (s.notFoundPaths || []).length
    ? `<div class="panel">
  <h2>top 404s (what scanners probe for)</h2>
  ${barList(s.notFoundPaths, { showBots: true })}
</div>`
    : ''
}

${
  (s.decoyPaths || []).length
    ? `<div class="panel">
  <h2>decoy endpoint hits (fake 200s for scanner probes)</h2>
  ${barList(s.decoyPaths, { showBots: true })}
</div>`
    : ''
}

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
      <td>${uaCell(u.ua_hash, u.ua, !!u.is_bot)}</td>
    </tr>`,
      )
      .join('')}
    </tbody>
  </table>
</div>

<footer>${SITE_LINK} &middot; data collected since first request &middot;
  <a href="/feed.xml">feed</a> &middot; <a href="/api/stats">json</a> &middot;
  <a href="/datenschutz">privacy</a></footer>`;
  return layout('useragents.nichtregistriert.de — statistics', body, { refresh: 30 });
}

export function renderUaDetail({ detail }) {
  const { meta: m, agg, trapDepth, worst, httpVersions, daily, paths, recent } = detail;

  const maxDay = Math.max(1, ...daily.map((d) => d.c));
  const spark = daily
    .map(
      (d) =>
        `<div style="height:${((d.c / maxDay) * 100).toFixed(1)}%" title="${esc(d.day)}: ${
          d.c
        }"></div>`,
    )
    .join('');

  const rows = [
    ['Classification', botTag(!!m.is_bot) + (m.bot_name ? ` <span class="muted">${esc(m.bot_name)}</span>` : '')],
    ['Browser', esc(m.browser || '—')],
    ['Operating system', esc(m.os || '—')],
    ['Device type', esc(m.device || '—')],
    ['First seen', esc(m.first_seen)],
    ['Last seen', esc(m.last_seen)],
    ['Total hits (catalogue)', Number(m.hits).toLocaleString('en')],
    ['Retained requests', `${Number(agg.logged).toLocaleString('en')}${
      agg.retained_from ? ` <span class="muted">(since ${esc(agg.retained_from)})</span>` : ''
    }`],
  ];

  const fpReasons = worst
    ? explainCodes(worst.spoof_reasons).map((r) => `<li>${esc(r)}</li>`).join('')
    : '';

  const body = `
<header>
  <h1>user-agent detail</h1>
  <p class="muted">${esc(m.ua_hash)}</p>
</header>
<nav><a href="/stats">&larr; statistics</a><a href="/feed.xml">feed</a></nav>

<div class="panel">
  <h2>User-Agent string</h2>
  <div class="ua-string">${esc(m.ua || '(no User-Agent header sent)')}</div>
</div>

<div class="panel">
  <h2>What we know</h2>
  <table><tbody>
    ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}
  </tbody></table>
</div>

<div class="panel">
  <h2>Behaviour</h2>
  <table><tbody>
    <tr><th>Honeypot hits</th><td>${Number(agg.honeypot_hits || 0).toLocaleString('en')}${
      trapDepth ? ` <span class="muted">— walked the maze to depth ${trapDepth}</span>` : ''
    }</td></tr>
    <tr><th>Decoy endpoint hits</th><td>${Number(agg.decoy_hits || 0).toLocaleString('en')}</td></tr>
    <tr><th>Header fingerprint</th><td>${
      worst
        ? `<span class="tag bot">MISMATCH</span> peak spoof score ${worst.spoof_score}
           <ul class="muted" style="margin:6px 0 0;padding-left:18px">${fpReasons}</ul>`
        : m.is_bot
          ? '<span class="muted">n/a — flagged as a bot by its UA string</span>'
          : '<span class="tag human">CONSISTENT</span> no failed header checks'
    }</td></tr>
    <tr><th>Client Hints sent</th><td>${Number(agg.client_hint_hits || 0).toLocaleString(
      'en',
    )} of ${Number(agg.logged).toLocaleString('en')} retained requests</td></tr>
    <tr><th>HTTP versions</th><td class="muted">${
      httpVersions.map((h) => `${esc(h.name)} (${h.c})`).join(', ') || '—'
    }</td></tr>
  </tbody></table>
</div>

<div class="panel">
  <h2>requests per day (last 30d)</h2>
  ${daily.length ? `<div class="spark">${spark}</div>` : '<p class="muted">no requests in the retention window</p>'}
</div>

<div class="panel">
  <h2>paths requested</h2>
  ${
    paths.length
      ? barList(
          paths.map((p) => ({
            label: p.path,
            badge: p.notfound ? '<span class="muted">· 404</span>' : '',
            c: p.c,
          })),
        )
      : '<p class="muted">no requests in the retention window</p>'
  }
</div>

<div class="panel">
  <h2>recent requests (${recent.length})</h2>
  ${
    recent.length
      ? `<table>
    <thead><tr><th>time (UTC)</th><th>method</th><th>path</th><th>status</th><th>source</th><th>spoof</th></tr></thead>
    <tbody>
    ${recent
      .map(
        (r) => `<tr>
      <td class="muted">${esc(r.ts)}</td>
      <td>${esc(r.method)}</td>
      <td class="mono-break">${esc(r.path)}</td>
      <td>${r.status}</td>
      <td class="muted">${esc(r.source)}</td>
      <td>${r.spoof_score || ''}</td>
    </tr>`,
      )
      .join('')}
    </tbody>
  </table>`
      : '<p class="muted">no requests in the retention window — the catalogue entry above survives pruning</p>'
  }
</div>

<footer>${SITE_LINK} &middot; <a href="/stats">all statistics</a> &middot;
  <a href="/datenschutz">privacy</a></footer>`;

  const name = m.bot_name || m.browser || 'unknown';
  return layout(`${name} — user-agent detail`, body);
}

export function renderNotFound({ path, dnt }) {
  const body = `
<header><h1>404</h1><p class="muted">no such resource: ${esc(path)}</p></header>
<p>${
    dnt
      ? 'This request was not logged (DNT/GPC or a self-exclusion is active).'
      : 'This request was still logged.'
  } <a href="/">go to the homepage</a> or see the
<a href="/stats">statistics</a>.</p>
<footer>${SITE_LINK} &middot; <a href="/datenschutz">privacy</a></footer>`;
  return layout('404', body);
}

export function renderPrivacy({ retentionDays } = {}) {
  const body = `
<header>
  <h1>privacy policy</h1>
  <p class="muted">Datenschutzerklärung — last updated 2026-09-11</p>
</header>
<nav><a href="/">&larr; home</a><a href="/stats">statistics</a></nav>

<div class="panel">
  <h2>Controller</h2>
  <p class="muted">
    Daniel Intrup<br>
    E-mail: <a href="mailto:din.trup@googlemail.com">din.trup@googlemail.com</a>
  </p>
  <p class="muted">
    This is a private, non-commercial hobby and security-research project run
    by an individual with no business interest in it — there is no separate
    "Impressum" (§5 DDG "Anbieterkennzeichnung"). The contact above covers
    anything a formal Impressum otherwise would.
  </p>
</div>

<div class="panel">
  <h2>What is collected, and why</h2>
  <p class="muted">This site's purpose is to observe and study which automated
  agents (bots, crawlers, scanners) access it, as a small piece of open security
  research. Every request — human or automated — is briefly processed to do that:</p>
  <table><tbody>
    <tr><th>Timestamp</th><td class="muted">to the second</td></tr>
    <tr><th>User-Agent string</th><td class="muted">as sent by the client, verbatim</td></tr>
    <tr><th>Requested path, method, status code</th><td class="muted">e.g. <code>GET /stats 200</code></td></tr>
    <tr><th>Referer</th><td class="muted"><strong>origin only</strong> (scheme + host) — the
      path and query string are discarded before anything is stored, since they can carry
      search terms or tokens that belong to a third-party site</td></tr>
    <tr><th>Accept-Language</th><td class="muted">as sent by the client</td></tr>
    <tr><th>Request-header fingerprint</th><td class="muted">whether Accept, Accept-Encoding,
      Sec-Fetch-*, Sec-CH-UA and the HTTP version are consistent with the claimed browser —
      see the landing page for what this looks like for your own request</td></tr>
    <tr><th>IP address</th><td class="muted"><strong>never stored.</strong> It is used only in
      memory, for the current request, to compute a SHA-256 hash of
      <code>secret_salt : today's date : ip</code>, truncated to 16 hex characters. The salt
      is generated once per server install, kept only in the database, and never leaves it —
      so the hash cannot be reversed back to an IP address, on this site or anywhere else. It
      changes every day, so the same visitor gets a new hash tomorrow.</td></tr>
  </tbody></table>
  <p class="muted">No cookies or browser storage are used for ordinary visitors, no
  JavaScript, and no third-party scripts, fonts, or requests of any kind. The one
  exception is a self-exclusion cookie the operator can set for their own testing
  traffic — see "Do Not Track" below.</p>
</div>

<div class="panel">
  <h2>Legal basis</h2>
  <p class="muted">Processing relies on <strong>legitimate interest</strong>
  (Art. 6(1)(f) GDPR): operating and securing a small, self-hosted research
  service, and studying automated web traffic. This is a narrow interest — no
  profiles are built across sites, no cookies or persistent identifiers are set
  in an ordinary visitor's browser, and raw IP addresses are never retained.</p>
</div>

<div class="panel">
  <h2>What is made public</h2>
  <p class="muted">
    <a href="/stats">/stats</a> and <a href="/api/stats">/api/stats</a> publish
    <strong>aggregate</strong> counts and categories — how many requests, bot vs.
    human, which browsers/OSes/devices, which paths were probed, and so on.
  </p>
  <p class="muted">
    <strong>Individual, timestamped request histories are published only for
    entries classified as bots or crawlers</strong> (<code>/stats/ua/&lt;hash&gt;</code>,
    linked from the statistics tables, the <a href="/feed.xml">Atom feed</a> and
    the sitemap). A human visitor's browser is never given its own public,
    linkable page — it is only ever reflected in the aggregate counts above.
    Automated agents are not natural persons and so are outside the scope of
    GDPR to begin with; this separation exists so publication never turns into
    a public log of an identifiable person's browsing activity.
  </p>
</div>

<div class="panel">
  <h2>Decoy endpoints</h2>
  <p class="muted">
    This server may answer a handful of well-known vulnerability-scanner paths
    (e.g. <code>/wp-login.php</code>, <code>/.env</code>) with a fake response
    instead of a 404, to study scanning behaviour. These pages accept no input,
    have no working form, and their content is entirely fabricated junk — no
    real system, credentials, or data exist behind them.
  </p>
</div>

<div class="panel">
  <h2>Retention</h2>
  <p class="muted">
    ${
      retentionDays > 0
        ? `Raw, per-request logs (the table backing the "recent requests" list on a
           bot's detail page) are deleted after <strong>${retentionDays} days</strong>.
           Once a human visitor's browser has been quiet for that same window, its
           aggregate catalogue entry (first/last seen, hit count) is deleted too.`
        : `Raw, per-request log retention is currently disabled on this instance
           (records are kept indefinitely) — ask the controller above if you'd like
           this changed.`
    }
    Aggregate history for <em>bots and crawlers</em> is kept indefinitely — that
    long-term "who crawls the web" record is this project's actual purpose, and
    bots are not people whose data must age out.
  </p>
</div>

<div class="panel">
  <h2>Do Not Track / Global Privacy Control</h2>
  <p class="muted">
    Send the <code>DNT: 1</code> or <code>Sec-GPC: 1</code> header and this site
    will serve your request normally but <strong>write nothing to its database</strong>
    — no row, no fingerprint, no contribution to any catalogue entry. Most current
    browsers can send <code>Sec-GPC</code> via a privacy extension or a built-in
    setting. Separately, the operator can unlock a long-lived, secret-gated
    <code>HttpOnly</code> cookie on their own browser for the same effect, so their
    own repeated testing traffic doesn't pollute the statistics — that cookie
    carries no information beyond "don't log this browser" and is never set for
    anyone who doesn't have the secret.
  </p>
</div>

<div class="panel">
  <h2>Your rights</h2>
  <p class="muted">
    Under the GDPR you have the right to access, rectify, erase, or restrict
    processing of your personal data, to object to it, and to data portability,
    as well as the right to lodge a complaint with a supervisory authority.
    Because this site stores no cookies, no account, and no raw IP address, it
    generally cannot look up "your" specific entries on request — if you believe
    a specific catalogue entry is about you (for instance, an unusually
    distinctive browser configuration) and want it deleted, contact the
    controller above with enough detail to identify it (approximate time,
    browser/OS) and it will be removed.
  </p>
</div>

<div class="panel">
  <h2>Hosting</h2>
  <p class="muted">
    This site is self-hosted by the controller above; no data is shared with
    or processed by any third-party service, analytics provider, or ad network.
  </p>
</div>

<footer>${SITE_LINK} &middot; <a href="/">home</a> &middot; <a href="/stats">statistics</a></footer>`;
  return layout('useragents.nichtregistriert.de — privacy policy', body);
}
