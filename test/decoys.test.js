import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { decoyFor, decoyPaths } from '../src/decoys.js';

describe('decoys', () => {
  test('known scanner paths return a decoy with a body and content type', () => {
    for (const path of decoyPaths()) {
      const d = decoyFor(path);
      assert.ok(d, `expected a decoy for ${path}`);
      assert.equal(typeof d.body, 'string');
      assert.ok(d.body.length > 0);
      assert.match(d.type, /^[a-z]+\/[a-z0-9.+-]+/i);
    }
  });

  test('/.env looks like Laravel config with an obviously fake password', () => {
    const d = decoyFor('/.env');
    assert.match(d.body, /APP_KEY=/);
    assert.match(d.body, /honeypot/i); // the fake DB_PASSWORD says what it is
  });

  test('unknown paths return null', () => {
    assert.equal(decoyFor('/definitely-not-a-real-path'), null);
    assert.equal(decoyFor('/'), null);
    assert.equal(decoyFor('/stats'), null);
  });

  test('decoyPaths() lists at least the classic scanner targets', () => {
    const paths = decoyPaths();
    for (const expected of ['/wp-login.php', '/.env', '/.git/config', '/xmlrpc.php']) {
      assert.ok(paths.includes(expected), `missing ${expected}`);
    }
  });
});
