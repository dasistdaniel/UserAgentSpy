import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseUA } from '../src/ua.js';
import { analyzeRequest } from '../src/fingerprint.js';
import {
  esc,
  renderIndex,
  renderStats,
  renderNotFound,
  renderPrivacy,
} from '../src/views.js';

describe('esc', () => {
  test('escapes the five HTML-special characters', () => {
    assert.equal(esc(`&<>"'`), '&amp;&lt;&gt;&quot;&#39;');
  });

  test('null/undefined become an empty string, not "null"/"undefined"', () => {
    assert.equal(esc(null), '');
    assert.equal(esc(undefined), '');
  });

  test('numbers are stringified', () => {
    assert.equal(esc(42), '42');
  });
});

describe('renderIndex', () => {
  test('renders a full page for a normal browser visit, UA safely escaped', () => {
    const ua = 'Mozilla/5.0 Chrome/141 Safari/537 <script>x</script>';
    const parsed = parseUA(ua);
    const fp = analyzeRequest({ httpVersion: '1.1', headers: {} }, parsed);
    const html = renderIndex({
      ua,
      parsed,
      fp,
      headers: {},
      ipHashShown: 'deadbeef',
      trapLinks: ['/trap/1/aaaa', '/trap/1/bbbb'],
      dnt: false,
    });
    assert.match(html, /<!doctype html>/);
    assert.ok(!html.includes('<script>x</script>'), 'the UA must be escaped, not injected raw');
    assert.match(html, /<link rel="stylesheet" href="\/style\.css\?v=/);
    assert.match(html, /<main class="wrap">/);
    for (const link of ['/trap/1/aaaa', '/trap/1/bbbb']) {
      assert.ok(html.includes(`href="${link}"`));
    }
  });

  test('shows the DNT/self-exclusion note instead of the storage explainer when dnt is true', () => {
    const parsed = parseUA('curl/8.0');
    const fp = analyzeRequest({ httpVersion: '1.1', headers: {} }, parsed);
    const html = renderIndex({
      ua: 'curl/8.0',
      parsed,
      fp,
      headers: {},
      ipHashShown: null,
      trapLinks: [],
      dnt: true,
    });
    assert.match(html, /not.*written to the database/s);
  });
});

describe('renderStats', () => {
  const minimalStats = () => ({
    generatedAt: new Date().toISOString(),
    filter: 'all',
    range: 'all',
    totals: {
      visits: 10,
      uas: 3,
      bot_visits: 7,
      bot_uas: 2,
      honeypot_hits: 1,
      decoy_hits: 0,
      last24h: 5,
      last7d: 10,
      spoofed_visits: 0,
      spoofed_uas: 0,
    },
    clientHints: { chromium_visits: 0, with_hints: 0 },
    spoofedUserAgents: [],
    topUserAgents: [
      {
        ua_hash: 'bothash',
        ua: 'GPTBot/1.0',
        hits: 7,
        is_bot: 1,
        bot_name: 'GPTBot',
        browser: 'Bot / library',
        os: 'Unknown',
        device: 'bot',
        last_seen: '2026-09-10 09:00:00',
      },
      {
        ua_hash: 'humanhash',
        ua: 'Mozilla/5.0 Chrome/141',
        hits: 3,
        is_bot: 0,
        bot_name: null,
        browser: 'Chrome',
        os: 'Windows 10/11',
        device: 'desktop',
        last_seen: '2026-09-10 09:00:00',
      },
    ],
    newestUserAgents: [],
    topBots: [{ name: 'GPTBot', c: 7 }],
    browsers: [{ name: 'Chrome', c: 3 }],
    oses: [{ name: 'Windows 10/11', c: 3 }],
    devices: [{ name: 'desktop', c: 3 }],
    topPaths: [{ path: '/', c: 10, bots: 7 }],
    statusCodes: [{ status: 200, c: 10, bots: 7 }],
    notFoundPaths: [],
    decoyPaths: [],
    daily: [{ day: '2026-09-10', c: 10, bots: 7 }],
  });

  test('renders without throwing and links only the bot UA, not the human one', () => {
    const html = renderStats(minimalStats());
    assert.match(html, /<!doctype html>/);
    assert.ok(html.includes('href="/stats/ua/bothash"'), 'bot UA should link to its detail page');
    assert.ok(
      !html.includes('href="/stats/ua/humanhash"'),
      'human UA must never get an individually-identifiable public link',
    );
  });

  test('filter/range pills mark the active choice and carry both params on links', () => {
    const s = minimalStats();
    s.filter = 'bots';
    s.range = '7d';
    const html = renderStats(s);
    // Both active pills point at the same URL (current filter + current range).
    assert.match(html, /href="\/stats\?filter=bots&range=7d"[^>]*class="on"/);
    // Switching one dimension must not drop the other: the inactive "humans"
    // pill still carries range=7d along with it.
    assert.match(html, /href="\/stats\?filter=humans&range=7d"/);
    assert.match(html, /href="\/api\/stats\?filter=bots&range=7d"/);
  });
});

describe('renderNotFound', () => {
  test('escapes the requested path', () => {
    const html = renderNotFound({ path: '/<script>', dnt: false });
    assert.ok(!html.includes('<script>'));
    assert.match(html, /&lt;script&gt;/);
  });
});

describe('renderPrivacy', () => {
  test('shows the configured retention window', () => {
    const html = renderPrivacy({ retentionDays: 42 });
    assert.match(html, /42 days/);
  });

  test('explains disabled retention when retentionDays is 0', () => {
    const html = renderPrivacy({ retentionDays: 0 });
    assert.match(html, /retention is currently disabled/);
  });
});
