// End-to-end tests: spawn the real server as a child process against a throwaway
// DB, exercise it over real HTTP, then inspect the SQLite file directly (once
// the server has shut down) for anything that's easier to prove that way than
// by fighting getStats()'s 8s cache.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

async function waitForServer(url, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet — keep polling
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`server at ${url} never became ready`);
}

function startServer(port, extraEnv = {}) {
  const dbDir = mkdtempSync(join(tmpdir(), 'uaspy-server-test-'));
  const dbPath = join(dbDir, 'app.db');
  const child = spawn(
    process.execPath,
    ['--disable-warning=ExperimentalWarning', 'src/server.js'],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        PORT: String(port),
        HOST: '127.0.0.1',
        DB_PATH: dbPath,
        BASE_URL: `http://127.0.0.1:${port}`,
        TRUST_PROXY: 'false',
        INDEXNOW_KEY: '',
        GOOGLE_VERIFY: '',
        ...extraEnv,
      },
      stdio: ['ignore', 'ignore', 'ignore'],
    },
  );
  return { child, dbDir, dbPath, base: `http://127.0.0.1:${port}` };
}

// Kills the child process. Safe to call more than once (a test may want the
// server down early to read its DB file with nothing else writing to it,
// and the after() hook calls this again — a no-op then).
async function killServer(server) {
  if (server.killed) return;
  server.killed = true;
  await new Promise((resolve) => {
    if (server.child.exitCode !== null || server.child.killed) return resolve();
    server.child.once('exit', resolve);
    server.child.kill('SIGTERM');
    setTimeout(() => {
      try {
        server.child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    }, 3000).unref();
  });
}

// Full teardown: kill + remove the temp DB directory. Only call this once
// (typically from an after() hook) — a test that needs to inspect the DB
// file mid-suite should call killServer() alone and leave cleanup to after().
async function stopServer(server) {
  await killServer(server);
  rmSync(server.dbDir, { recursive: true, force: true });
}

function cookieValue(setCookieHeader) {
  return setCookieHeader.split(';')[0]; // "name=value", strip Path/Max-Age/etc.
}

describe('server (main instance)', () => {
  let server;

  before(async () => {
    server = startServer(18173, {
      FAKE_ENDPOINTS: 'true',
      NOLOG_KEY: 'test-nolog-secret',
      RATE_LIMIT_MAX: '1000', // generous — this suite makes many requests
    });
    await waitForServer(`${server.base}/healthz`);
  });

  after(() => stopServer(server));

  test('/ serves 200 for both a human and a bot User-Agent', async () => {
    const human = await fetch(server.base + '/', {
      headers: { 'user-agent': 'Mozilla/5.0 Chrome/141 Safari/537' },
    });
    assert.equal(human.status, 200);
    assert.match(await human.text(), /<!doctype html>/);

    const bot = await fetch(server.base + '/', {
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
    });
    assert.equal(bot.status, 200);
  });

  test('POST / is 405 with an Allow header', async () => {
    const res = await fetch(server.base + '/', { method: 'POST' });
    assert.equal(res.status, 405);
    assert.equal(res.headers.get('allow'), 'GET, HEAD');
  });

  test('unknown paths are 404', async () => {
    const res = await fetch(server.base + '/this-does-not-exist');
    assert.equal(res.status, 404);
  });

  test('the core discovery/meta routes all serve 200 with sane content types', async () => {
    const routes = [
      ['/stats', /text\/html/],
      ['/api/stats', /application\/json/],
      ['/robots.txt', /text\/plain/],
      ['/sitemap.xml', /application\/xml/],
      ['/llms.txt', /text\/plain/],
      ['/style.css', /text\/css/],
      ['/datenschutz', /text\/html/],
      ['/feed.xml', /application\/atom\+xml/],
    ];
    for (const [path, contentType] of routes) {
      const res = await fetch(server.base + path);
      assert.equal(res.status, 200, path);
      assert.match(res.headers.get('content-type') || '', contentType, path);
    }
  });

  test('/style.css is cached "forever" and versioned', async () => {
    const res = await fetch(server.base + '/style.css');
    assert.match(res.headers.get('cache-control') || '', /immutable/);
    const html = await (await fetch(server.base + '/')).text();
    assert.match(html, /\/style\.css\?v=[0-9a-f]+/);
  });

  test('decoy endpoints answer 200 when FAKE_ENDPOINTS is on', async () => {
    const res = await fetch(server.base + '/wp-login.php');
    assert.equal(res.status, 200);
    const env = await fetch(server.base + '/.env');
    assert.match(await env.text(), /honeypot/i);
  });

  test('bot detail pages are public, human detail pages 404', async () => {
    await fetch(server.base + '/', {
      headers: { 'user-agent': 'DetailTestBot/1.0 (+https://example.com/bot)' },
    });
    await fetch(server.base + '/', {
      headers: { 'user-agent': 'Mozilla/5.0 DetailTestHuman/1.0 Chrome/141 Safari/537' },
    });
    // A distinct, not-yet-queried filter/range combo — getStats() caches per
    // key for 8s, and an earlier test already primed the plain "all:all" one.
    const stats = await (await fetch(server.base + '/api/stats?range=24h')).json();
    const bot = stats.topUserAgents.find((u) => u.ua.startsWith('DetailTestBot'));
    const human = stats.topUserAgents.find((u) => u.ua.startsWith('Mozilla/5.0 DetailTestHuman'));
    assert.ok(bot && human, 'both test UAs should show up in topUserAgents');

    const botPage = await fetch(server.base + `/stats/ua/${bot.ua_hash}`);
    assert.equal(botPage.status, 200);
    const humanPage = await fetch(server.base + `/stats/ua/${human.ua_hash}`);
    assert.equal(humanPage.status, 404);
  });

  test('DNT: 1 is served normally but not written to the database', async () => {
    const res = await fetch(server.base + '/', {
      headers: { 'user-agent': 'DntTestUA/1.0', dnt: '1' },
    });
    assert.equal(res.status, 200);
    assert.match(await res.text(), /not.*written to the database/s);
  });

  test('the NOLOG cookie flow excludes the browser from logging', async () => {
    const unlock = await fetch(server.base + '/?nolog=test-nolog-secret', {
      headers: { 'user-agent': 'NologTestUA/1.0' },
    });
    const setCookie = unlock.headers.get('set-cookie');
    assert.ok(setCookie, 'expected a Set-Cookie on unlock');
    const cookie = cookieValue(setCookie);

    const followUp = await fetch(server.base + '/some/other/path', {
      headers: { 'user-agent': 'NologTestUA/1.0', cookie },
    });
    assert.equal(followUp.status, 404); // route doesn't exist, but that's fine — we're checking logging
  });

  test('nothing DNT-tagged or NOLOG-excluded ends up in the database', async () => {
    await killServer(server); // no more writers before reading the file directly
    const db = new DatabaseSync(server.dbPath, { readOnly: true });
    try {
      const dnt = db.prepare("SELECT COUNT(*) AS c FROM visits WHERE ua = 'DntTestUA/1.0'").get();
      assert.equal(dnt.c, 0);
      const nolog = db.prepare("SELECT COUNT(*) AS c FROM visits WHERE ua = 'NologTestUA/1.0'").get();
      assert.equal(nolog.c, 0);
      const decoy = db
        .prepare("SELECT COUNT(*) AS c FROM visits WHERE path = '/wp-login.php' AND source = 'decoy'")
        .get();
      assert.equal(decoy.c, 1);
    } finally {
      db.close();
    }
  });
});

describe('server (rate limiting, isolated instance)', () => {
  let server;

  before(async () => {
    server = startServer(18174, { RATE_LIMIT_MAX: '3', RATE_LIMIT_WINDOW_S: '10' });
    await waitForServer(`${server.base}/healthz`);
  });

  after(() => stopServer(server));

  test('requests beyond the limit get 429 and are never logged', async () => {
    const codes = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(server.base + '/', { headers: { 'user-agent': 'RateLimitTestUA/1.0' } });
      codes.push(res.status);
    }
    assert.deepEqual(codes.slice(0, 3), [200, 200, 200]);
    assert.ok(codes.slice(3).every((c) => c === 429), `expected 429s, got ${codes}`);

    const last = await fetch(server.base + '/', { headers: { 'user-agent': 'RateLimitTestUA/1.0' } });
    assert.equal(last.status, 429);
    assert.ok(last.headers.get('retry-after'));

    await killServer(server); // no more writers before reading the file directly
    const db = new DatabaseSync(server.dbPath, { readOnly: true });
    try {
      const row = db
        .prepare("SELECT COUNT(*) AS c FROM visits WHERE ua = 'RateLimitTestUA/1.0'")
        .get();
      assert.equal(row.c, 3, 'only the allowed requests should be written to the DB');
    } finally {
      db.close();
    }
  });
});
