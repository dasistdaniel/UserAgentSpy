// Sets VISITS_RETENTION_DAYS before dynamically importing db.js, since that
// module reads it once at import time — a static top-level import would run
// (and capture the default) before this file's own code gets to set it.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.VISITS_RETENTION_DAYS = '30';

const dbDir = mkdtempSync(join(tmpdir(), 'uaspy-db-test-'));
const dbPath = join(dbDir, 'app.db');

const {
  initDb,
  recordVisit,
  getStats,
  getUserAgentDetail,
  recentUserAgents,
  pruneVisits,
  retentionDays,
  closeDb,
} = await import('../src/db.js');

initDb(dbPath);

const fmt = (d) => d.toISOString().slice(0, 19).replace('T', ' ');
const now = () => fmt(new Date());
const daysAgo = (n) => fmt(new Date(Date.now() - n * 24 * 60 * 60 * 1000));

function botVisit({ ts, ua, path = '/' }) {
  recordVisit({
    ts,
    ua,
    parsed: {
      isBot: true, botName: ua.split('/')[0], browser: 'Bot / library',
      browserVersion: null, os: 'Unknown', device: 'bot',
    },
    fp: { httpVersion: '1.1', clientHints: false, spoofScore: 0, codes: [] },
    path, method: 'GET', status: 200, source: 'direct',
  });
}

function humanVisit({ ts, ua, path = '/' }) {
  recordVisit({
    ts,
    ua,
    parsed: {
      isBot: false, botName: null, browser: 'Chrome',
      browserVersion: '141', os: 'Windows 10/11', device: 'desktop',
    },
    fp: { httpVersion: '1.1', clientHints: true, spoofScore: 0, codes: [] },
    path, method: 'GET', status: 200, source: 'direct',
  });
}

// --- seed data -------------------------------------------------------------
// Recent (within the 30-day retention window):
botVisit({ ts: now(), ua: 'FreshBot/1.0' });
botVisit({ ts: now(), ua: 'FreshBot/1.0' }); // second hit, same UA
humanVisit({ ts: now(), ua: 'FreshHuman/1.0 Chrome/141' });
// Old (past the 30-day window) — one bot, one human, each a UA seen only once:
botVisit({ ts: daysAgo(200), ua: 'OldBot/1.0', path: '/old' });
humanVisit({ ts: daysAgo(200), ua: 'OldHuman/1.0 Chrome/141', path: '/old' });

const hashOf = (ua) => recentUserAgents(50).find((u) => u.ua === ua)?.ua_hash;

after(() => {
  closeDb();
  rmSync(dbDir, { recursive: true, force: true });
});

describe('getStats', () => {
  test('all:all reflects every recorded row (unfiltered totals)', () => {
    const s = getStats('all', 'all');
    assert.equal(s.filter, 'all');
    assert.equal(s.range, 'all');
    assert.ok(s.totals.visits >= 5);
    assert.ok(s.totals.uas >= 4);
  });

  test('bots:all narrows topUserAgents/newestUserAgents to is_bot=1', () => {
    const s = getStats('bots', 'all');
    assert.ok(s.topUserAgents.length > 0);
    assert.ok(s.topUserAgents.every((u) => u.is_bot === 1));
  });

  test('humans:all narrows to is_bot=0', () => {
    const s = getStats('humans', 'all');
    assert.ok(s.topUserAgents.length > 0);
    assert.ok(s.topUserAgents.every((u) => u.is_bot === 0));
  });
});

describe('recentUserAgents', () => {
  test('botsOnly excludes human entries', () => {
    const bots = recentUserAgents(50, { botsOnly: true });
    assert.ok(bots.length > 0);
    assert.ok(bots.every((u) => u.is_bot === 1));
    assert.ok(!bots.some((u) => u.ua === 'FreshHuman/1.0 Chrome/141'));
  });
});

describe('getUserAgentDetail', () => {
  test('returns null for a UA that was never seen', () => {
    assert.equal(getUserAgentDetail('never-seen-hash'), null);
  });

  test('returns full detail for a known bot, including hit count', () => {
    const hash = hashOf('FreshBot/1.0');
    const detail = getUserAgentDetail(hash);
    assert.ok(detail);
    assert.equal(detail.meta.is_bot, 1);
    assert.equal(detail.meta.hits, 2);
    assert.equal(detail.recent.length, 2);
  });
});

describe('pruneVisits', () => {
  test('reports the configured retention window', () => {
    assert.equal(retentionDays(), 30);
  });

  test('deletes old visit rows and quiet human catalogue rows, keeps bots forever', () => {
    const oldBotHash = hashOf('OldBot/1.0');
    const oldHumanHash = hashOf('OldHuman/1.0 Chrome/141');
    const freshBotHash = hashOf('FreshBot/1.0');

    const result = pruneVisits();
    assert.equal(result.visits, 2); // the two 200-day-old rows
    assert.equal(result.humanUas, 1); // the one quiet human catalogue row

    // Old bot: visits row pruned, but the catalogue entry survives forever.
    const oldBot = getUserAgentDetail(oldBotHash);
    assert.ok(oldBot, 'bot catalogue row must survive pruning');
    assert.equal(oldBot.agg.logged, 0);

    // Old human: both the visit row AND the catalogue row are gone.
    assert.equal(getUserAgentDetail(oldHumanHash), null);

    // Recent bot is untouched.
    const freshBot = getUserAgentDetail(freshBotHash);
    assert.equal(freshBot.agg.logged, 2);
  });

  test('is idempotent — a second call has nothing left to delete', () => {
    const result = pruneVisits();
    assert.equal(result.visits, 0);
    assert.equal(result.humanUas, 0);
  });
});
