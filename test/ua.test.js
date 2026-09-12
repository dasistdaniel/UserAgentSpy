import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseUA } from '../src/ua.js';

describe('parseUA', () => {
  test('empty User-Agent is treated as a bot', () => {
    const p = parseUA('');
    assert.equal(p.isBot, true);
    assert.equal(p.empty, true);
    assert.equal(p.device, 'bot');
  });

  test('missing/undefined User-Agent behaves like empty', () => {
    const p = parseUA(undefined);
    assert.equal(p.isBot, true);
    assert.equal(p.empty, true);
  });

  test('a real Chrome/Windows desktop UA parses as human', () => {
    const ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
    const p = parseUA(ua);
    assert.equal(p.isBot, false);
    assert.equal(p.browser, 'Chrome');
    assert.equal(p.browserVersion, '141.0.0.0');
    assert.equal(p.os, 'Windows 10/11');
    assert.equal(p.device, 'desktop');
  });

  test('Firefox is detected', () => {
    const ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0';
    const p = parseUA(ua);
    assert.equal(p.browser, 'Firefox');
    assert.equal(p.os, 'Linux');
  });

  test('Safari on iOS is mobile', () => {
    const ua =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 ' +
      '(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
    const p = parseUA(ua);
    assert.equal(p.browser, 'Safari');
    assert.equal(p.os, 'iOS 17.4');
    assert.equal(p.device, 'mobile');
  });

  test('an iPad is a tablet, not mobile', () => {
    const ua =
      'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 ' +
      '(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
    const p = parseUA(ua);
    assert.equal(p.device, 'tablet');
  });

  test('Googlebot is classified as a bot with the right name', () => {
    const ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    const p = parseUA(ua);
    assert.equal(p.isBot, true);
    assert.match(p.botName, /googlebot/i);
    assert.equal(p.device, 'bot');
  });

  test('generic "bot" token in the name is caught', () => {
    const p = parseUA('SomeWeirdCrawlerBot/1.0');
    assert.equal(p.isBot, true);
  });

  test('a bare URL in the UA (contact address) marks it a bot', () => {
    const p = parseUA('MyLittleScraper (+https://example.com/about)');
    assert.equal(p.isBot, true);
  });

  test('common HTTP libraries are flagged as bots', () => {
    for (const ua of ['curl/8.7.1', 'python-requests/2.31.0', 'Go-http-client/1.1']) {
      assert.equal(parseUA(ua).isBot, true, ua);
    }
  });

  test('curl is also recognized as a "browser" name for display', () => {
    const p = parseUA('curl/8.7.1');
    assert.equal(p.browser, 'curl');
    assert.equal(p.browserVersion, '8.7.1');
  });

  test('a real browser is never flagged as a bot', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15';
    assert.equal(parseUA(ua).isBot, false);
  });

  test('unknown browser falls back to "Bot / library" only when flagged as a bot', () => {
    const bot = parseUA('nuclei/3.0');
    assert.equal(bot.isBot, true);
    assert.equal(bot.browser, 'Bot / library');

    const human = parseUA('SomeTotallyUnknownClient/1.0');
    assert.equal(human.isBot, false);
    assert.equal(human.browser, 'Unknown');
  });
});
