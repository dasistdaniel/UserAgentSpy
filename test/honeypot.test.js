import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_DEPTH,
  seedTrapLinks,
  nextTrapLinks,
  parseTrapPath,
} from '../src/honeypot.js';

describe('honeypot maze', () => {
  test('seedTrapLinks() returns a handful of depth-1 links', () => {
    const links = seedTrapLinks();
    assert.ok(links.length > 0);
    for (const l of links) assert.match(l, /^\/trap\/1\/[a-f0-9]+$/);
  });

  test('seedTrapLinks() is deterministic (same tokens every call)', () => {
    assert.deepEqual(seedTrapLinks(), seedTrapLinks());
  });

  test('nextTrapLinks() advances the depth in every returned link', () => {
    const [firstLink] = seedTrapLinks();
    const trap = parseTrapPath(firstLink);
    const children = nextTrapLinks(trap.token, trap.depth);
    assert.ok(children.length > 0);
    for (const c of children) assert.match(c, new RegExp(`^/trap/${trap.depth + 1}/[a-f0-9]+$`));
  });

  test('the maze is bounded: no links past MAX_DEPTH', () => {
    assert.deepEqual(nextTrapLinks('anytoken', MAX_DEPTH), []);
    assert.deepEqual(nextTrapLinks('anytoken', MAX_DEPTH + 5), []);
  });

  test('walking depth by depth never exceeds MAX_DEPTH', () => {
    let [link] = seedTrapLinks();
    let depth = 1;
    while (depth < MAX_DEPTH) {
      const trap = parseTrapPath(link);
      assert.ok(trap.depth <= MAX_DEPTH);
      const next = nextTrapLinks(trap.token, trap.depth);
      assert.ok(next.length > 0, `expected children at depth ${trap.depth}`);
      [link] = next;
      depth += 1;
    }
    assert.deepEqual(nextTrapLinks(parseTrapPath(link).token, MAX_DEPTH), []);
  });

  test('parseTrapPath rejects malformed or out-of-range paths', () => {
    assert.equal(parseTrapPath('/trap/0/abcd1234'), null); // depth 0 invalid
    assert.equal(parseTrapPath(`/trap/${MAX_DEPTH + 1}/abcd1234`), null);
    assert.equal(parseTrapPath('/trap/abc/abcd1234'), null); // non-numeric depth
    assert.equal(parseTrapPath('/trap/1/xyz'), null); // token too short / not hex
    assert.equal(parseTrapPath('/stats'), null);
  });

  test('parseTrapPath round-trips a valid seed link', () => {
    const [link] = seedTrapLinks();
    const trap = parseTrapPath(link);
    assert.equal(trap.depth, 1);
    assert.match(trap.token, /^[a-f0-9]+$/);
  });
});
