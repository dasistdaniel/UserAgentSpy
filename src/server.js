import http from 'node:http';
import crypto from 'node:crypto';

import {
  initDb, getSalt, getMeta, setMeta, recordVisit, getStats,
  recentUserAgents, pruneVisits, retentionDays, closeDb,
} from './db.js';
import { indexNowKey, maybePingIndexNow } from './indexnow.js';
import { parseUA } from './ua.js';
import { analyzeRequest } from './fingerprint.js';
import { renderAtom } from './feed.js';
import {
  renderIndex,
  renderStats,
  renderTrap,
  renderNotFound,
} from './views.js';
import { seedTrapLinks, nextTrapLinks, parseTrapPath } from './honeypot.js';

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DB_PATH = process.env.DB_PATH || './data/app.db';
const BASE_URL = (process.env.BASE_URL || 'http://localhost:' + PORT).replace(/\/$/, '');
const TRUST_PROXY = /^(1|true|yes|on)$/i.test(process.env.TRUST_PROXY || '');

// Public URLs we advertise in sitemap.xml and push to IndexNow.
const SITE_PATHS = ['/', '/stats'];
const INDEXNOW_KEY = indexNowKey();

// Google Search Console file verification: set to the token from the
// googleXXXX.html file Google hands you (with or without the .html suffix).
const GOOGLE_VERIFY = (process.env.GOOGLE_VERIFY || '')
  .trim()
  .replace(/\.html$/i, '');

initDb(DB_PATH);
const SALT = getSalt();

// Salted, daily-rotating IP hash. We never store the raw address.
function ipHash(ip) {
  if (!ip) return null;
  const day = new Date().toISOString().slice(0, 10);
  return crypto
    .createHash('sha256')
    .update(`${SALT}:${day}:${ip}`)
    .digest('hex')
    .slice(0, 16);
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
    const xr = req.headers['x-real-ip'];
    if (xr) return String(xr).trim();
  }
  return req.socket.remoteAddress || '';
}

const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

// /stats + /api/stats accept ?filter=bots|humans (anything else => all).
const statsFilter = (v) => (v === 'bots' || v === 'humans' ? v : 'all');

// Paths we serve but do NOT want polluting the visit log.
const SKIP_LOG = new Set(['/api/stats', '/healthz', '/favicon.ico']);

function send(res, status, body, type = 'text/html; charset=utf-8', extra = {}) {
  res.writeHead(status, {
    'content-type': type,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    ...extra,
  });
  res.end(body);
}

function log(req, status, pathname) {
  const ua = req.headers['user-agent'] || '-';
  process.stdout.write(
    `${now()} ${req.method} ${pathname} ${status} "${ua.slice(0, 120)}"\n`,
  );
}

const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url, BASE_URL);
  } catch {
    return send(res, 400, 'bad request', 'text/plain');
  }
  const pathname = decodeURIComponent(url.pathname).replace(/\/{2,}/g, '/');
  const ua = req.headers['user-agent'] || '';
  const parsed = parseUA(ua);
  const fp = analyzeRequest(req, parsed);

  let status = 200;
  let source = 'direct';
  let handled = false;
  let bodyOut = '';

  // ---- routing ---------------------------------------------------------------
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    status = 405;
    bodyOut = 'method not allowed';
    send(res, 405, bodyOut, 'text/plain', { allow: 'GET, HEAD' });
    handled = true;
  } else if (pathname === '/' ) {
    bodyOut = renderIndex({
      ua,
      parsed,
      fp,
      headers: req.headers,
      ipHashShown: ipHash(clientIp(req)),
      trapLinks: seedTrapLinks(),
    });
    send(res, 200, bodyOut);
    handled = true;
  } else if (pathname === '/stats') {
    bodyOut = renderStats(getStats(statsFilter(url.searchParams.get('filter'))));
    send(res, 200, bodyOut);
    handled = true;
  } else if (pathname === '/api/stats') {
    const data = getStats(statsFilter(url.searchParams.get('filter')));
    send(res, 200, JSON.stringify(data, null, 2), 'application/json; charset=utf-8', {
      'access-control-allow-origin': '*',
    });
    handled = true;
  } else if (pathname === '/healthz') {
    send(res, 200, 'ok', 'text/plain');
    handled = true;
  } else if (pathname === '/favicon.ico') {
    status = 204;
    send(res, 204, '');
    handled = true;
  } else if (pathname === '/robots.txt') {
    send(
      res,
      200,
      `User-agent: *\nAllow: /\n\nSitemap: ${BASE_URL}/sitemap.xml\n`,
      'text/plain; charset=utf-8',
    );
    handled = true;
  } else if (pathname === '/sitemap.xml') {
    const lastmod = new Date().toISOString().slice(0, 10);
    const urls = SITE_PATHS.map(
      (p) =>
        `  <url><loc>${BASE_URL}${p}</loc><lastmod>${lastmod}</lastmod>` +
        `<changefreq>daily</changefreq><priority>${p === '/' ? '1.0' : '0.8'}</priority></url>`,
    );
    send(
      res,
      200,
      `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`,
      'application/xml; charset=utf-8',
    );
    handled = true;
  } else if (pathname === '/feed.xml') {
    send(
      res,
      200,
      renderAtom({ baseUrl: BASE_URL, entries: recentUserAgents(50) }),
      'application/atom+xml; charset=utf-8',
    );
    handled = true;
  } else if (INDEXNOW_KEY && pathname === `/${INDEXNOW_KEY}.txt`) {
    // IndexNow ownership-verification file.
    send(res, 200, INDEXNOW_KEY, 'text/plain; charset=utf-8');
    handled = true;
  } else if (GOOGLE_VERIFY && pathname === `/${GOOGLE_VERIFY}.html`) {
    // Google Search Console ownership-verification file.
    send(res, 200, `google-site-verification: ${GOOGLE_VERIFY}.html`, 'text/html; charset=utf-8');
    handled = true;
  } else if (pathname.startsWith('/trap/')) {
    const trap = parseTrapPath(pathname);
    if (trap) {
      source = 'honeypot';
      bodyOut = renderTrap({
        depth: trap.depth,
        links: nextTrapLinks(trap.token, trap.depth),
      });
      send(res, 200, bodyOut);
      handled = true;
    }
  }

  if (!handled) {
    status = 404;
    bodyOut = renderNotFound({ path: pathname });
    send(res, 404, bodyOut);
  }

  // ---- logging --------------------------------------------------------------
  log(req, status, pathname);
  if (!SKIP_LOG.has(pathname)) {
    try {
      recordVisit({
        ts: now(),
        ua,
        parsed,
        fp,
        path: pathname.slice(0, 512),
        method: req.method,
        status,
        referer: (req.headers['referer'] || '').slice(0, 512) || null,
        acceptLanguage: (req.headers['accept-language'] || '').slice(0, 256) || null,
        ipHash: ipHash(clientIp(req)),
        source,
      });
    } catch (err) {
      process.stderr.write(`recordVisit failed: ${err.stack || err}\n`);
    }
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(
    `useragents.nichtregistriert.de listening on http://${HOST}:${PORT}  (base: ${BASE_URL}, proxy-trust: ${TRUST_PROXY})\n`,
  );

  maybePingIndexNow({
    baseUrl: BASE_URL,
    urls: SITE_PATHS.map((p) => BASE_URL + p),
    getMeta,
    setMeta,
  })
    .then((r) => process.stdout.write(`indexnow: ${JSON.stringify(r)}\n`))
    .catch((err) => process.stderr.write(`indexnow failed: ${err.stack || err}\n`));

  runPrune();
  setInterval(runPrune, 24 * 60 * 60 * 1000).unref();
});

// Drop raw visit rows past the retention window; the user_agents catalogue stays.
function runPrune() {
  try {
    const n = pruneVisits();
    if (n === null) {
      process.stdout.write('prune: disabled (VISITS_RETENTION_DAYS <= 0)\n');
    } else if (n > 0) {
      process.stdout.write(`prune: deleted ${n} visit rows older than ${retentionDays()}d\n`);
    }
  } catch (err) {
    process.stderr.write(`prune failed: ${err.stack || err}\n`);
  }
}

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    process.stdout.write(`\n${sig} received, shutting down\n`);
    server.close(() => {
      closeDb();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
