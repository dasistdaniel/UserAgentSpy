import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseUA } from '../src/ua.js';
import { analyzeRequest, explainCodes, SPOOF_THRESHOLD } from '../src/fingerprint.js';

const chromeUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

describe('analyzeRequest', () => {
  test('a fully-consistent Chrome request scores 0 and is not spoofed', () => {
    const req = {
      httpVersion: '1.1',
      headers: {
        accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-dest': 'document',
        'sec-ch-ua': '"Chromium";v="141"',
      },
    };
    const fp = analyzeRequest(req, parseUA(chromeUA));
    assert.equal(fp.spoofScore, 0);
    assert.equal(fp.spoofed, false);
    assert.equal(fp.claimsBrowser, true);
    assert.deepEqual(fp.codes, []);
  });

  test('a bare Chrome UA with curl-default headers scores high and is spoofed', () => {
    const req = { httpVersion: '1.1', headers: {} }; // curl sends Accept: */* by default
    req.headers.accept = '*/*';
    const fp = analyzeRequest(req, parseUA(chromeUA));
    assert.ok(fp.spoofScore >= SPOOF_THRESHOLD, `expected >= ${SPOOF_THRESHOLD}, got ${fp.spoofScore}`);
    assert.equal(fp.spoofed, true);
    assert.ok(fp.codes.includes('accept_star'));
    assert.ok(fp.codes.includes('no_accept_encoding'));
    assert.ok(fp.codes.includes('no_sec_fetch'));
    assert.ok(fp.codes.includes('no_client_hints'));
  });

  test('a real bot (by UA) is never scored for spoofing, even with bare headers', () => {
    const req = { httpVersion: '1.1', headers: {} };
    const fp = analyzeRequest(req, parseUA('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'));
    assert.equal(fp.claimsBrowser, false);
    assert.equal(fp.spoofScore, 0);
    assert.deepEqual(fp.codes, []);
  });

  test('a From header adds a signal regardless of what the UA claims', () => {
    const req = { httpVersion: '1.1', headers: { from: 'crawler@example.com' } };
    const fp = analyzeRequest(req, parseUA('SomeApp/1.0'));
    assert.ok(fp.codes.includes('from_header'));
    assert.ok(fp.spoofScore >= 4);
  });

  test('HTTP/1.0 requests are flagged when claiming a browser', () => {
    const req = {
      httpVersion: '1.0',
      headers: {
        accept: 'text/html',
        'accept-encoding': 'gzip',
        'accept-language': 'en',
        'sec-fetch-mode': 'navigate',
      },
    };
    const fp = analyzeRequest(req, parseUA(chromeUA));
    assert.ok(fp.codes.includes('http_1_0'));
  });

  test('an old Chromium version is not penalized for missing Client Hints', () => {
    const oldChrome =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/70.0.0.0 Safari/537.36'; // < 90
    const req = {
      httpVersion: '1.1',
      headers: {
        accept: 'text/html',
        'accept-encoding': 'gzip',
        'accept-language': 'en',
        'sec-fetch-mode': 'navigate',
      },
    };
    const fp = analyzeRequest(req, parseUA(oldChrome));
    assert.ok(!fp.codes.includes('no_client_hints'));
  });

  test('non-Chromium browsers (Firefox/Safari) are never checked for Client Hints', () => {
    const req = {
      httpVersion: '1.1',
      headers: {
        accept: 'text/html',
        'accept-encoding': 'gzip',
        'accept-language': 'en',
        'sec-fetch-mode': 'navigate',
      },
    };
    const fp = analyzeRequest(req, parseUA('Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0'));
    assert.ok(!fp.codes.includes('no_client_hints'));
  });
});

describe('explainCodes', () => {
  test('maps known codes to their human-readable text', () => {
    const texts = explainCodes('no_accept,http_1_0');
    assert.equal(texts.length, 2);
    assert.match(texts[0], /Accept header/);
    assert.match(texts[1], /HTTP\/1\.0/);
  });

  test('handles empty/null input without throwing', () => {
    assert.deepEqual(explainCodes(''), []);
    assert.deepEqual(explainCodes(null), []);
    assert.deepEqual(explainCodes(undefined), []);
  });

  test('falls back to the raw code for anything unrecognized', () => {
    assert.deepEqual(explainCodes('totally_unknown_code'), ['totally_unknown_code']);
  });
});
