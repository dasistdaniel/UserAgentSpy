import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { renderAtom } from '../src/feed.js';

const baseUrl = 'https://useragents.nichtregistriert.de';

describe('renderAtom', () => {
  test('produces a well-formed-looking Atom feed with one entry per UA', () => {
    const xml = renderAtom({
      baseUrl,
      entries: [
        {
          ua_hash: 'abc123',
          ua: 'GPTBot/1.0',
          first_seen: '2026-09-10 09:00:00',
          last_seen: '2026-09-10 09:05:00',
          hits: 3,
          is_bot: 1,
          bot_name: 'GPTBot',
          browser: 'Bot / library',
          os: 'Unknown',
          device: 'bot',
        },
        {
          ua_hash: 'def456',
          ua: 'Mozilla/5.0 Chrome/141',
          first_seen: '2026-09-10 08:00:00',
          last_seen: '2026-09-10 08:00:00',
          hits: 1,
          is_bot: 0,
          bot_name: null,
          browser: 'Chrome',
          os: 'Windows 10/11',
          device: 'desktop',
        },
      ],
    });

    assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
    assert.equal((xml.match(/<entry>/g) || []).length, 2);
    assert.match(xml, /<id>tag:useragents\.nichtregistriert\.de,2026:ua\/abc123<\/id>/);
    assert.match(
      xml,
      /<link href="https:\/\/useragents\.nichtregistriert\.de\/stats\/ua\/abc123"\/>/,
    );
    assert.match(xml, /Bot: GPTBot/);
  });

  test('escapes a malicious/odd User-Agent so it cannot break the XML', () => {
    const xml = renderAtom({
      baseUrl,
      entries: [
        {
          ua_hash: 'evil1',
          ua: '<script>alert(1)</script>&"\'',
          first_seen: '2026-09-10 09:00:00',
          last_seen: '2026-09-10 09:00:00',
          hits: 1,
          is_bot: 1,
          bot_name: null,
          browser: 'Bot / library',
          os: 'Unknown',
          device: 'bot',
        },
      ],
    });
    assert.ok(!xml.includes('<script>'), 'raw <script> tag must not appear unescaped');
    assert.ok(xml.includes('&lt;script&gt;'));
    assert.ok(xml.includes('&amp;'));
  });

  test('an empty entries list still produces a valid, entry-less feed', () => {
    const xml = renderAtom({ baseUrl, entries: [] });
    assert.match(xml, /<feed xmlns="http:\/\/www\.w3\.org\/2005\/Atom">/);
    assert.ok(!xml.includes('<entry>'));
  });
});
