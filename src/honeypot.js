import crypto from 'node:crypto';

// A bounded "crawler maze": every trap page links to a handful of deeper trap pages,
// deterministically derived from a token so the space is large but reproducible.
// Depth is capped so we never build an infinite structure.

export const MAX_DEPTH = 8;
const FANOUT = 4;
const SECRET = process.env.TRAP_SECRET || 'useragents-spy-trap';

const tokenAt = (seed, depth, i) =>
  crypto
    .createHash('sha1')
    .update(`${SECRET}:${seed}:${depth}:${i}`)
    .digest('hex')
    .slice(0, 16);

// Links to place (hidden) on the landing page — entry points into the maze.
export function seedTrapLinks() {
  return Array.from({ length: FANOUT }, (_, i) => `/trap/1/${tokenAt('root', 1, i)}`);
}

// Given a trap page at (depth, token), the links it should expose.
export function nextTrapLinks(token, depth) {
  if (depth >= MAX_DEPTH) return [];
  return Array.from(
    { length: FANOUT },
    (_, i) => `/trap/${depth + 1}/${tokenAt(token, depth + 1, i)}`,
  );
}

export function parseTrapPath(pathname) {
  const m = pathname.match(/^\/trap\/(\d{1,2})\/([a-f0-9]{4,32})$/);
  if (!m) return null;
  const depth = parseInt(m[1], 10);
  if (depth < 1 || depth > MAX_DEPTH) return null;
  return { depth, token: m[2] };
}
