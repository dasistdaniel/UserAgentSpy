// IndexNow: a one-line ping that tells Bing + Yandex (and their partners) to come
// crawl our URLs. Zero deps — uses the built-in global fetch.
// https://www.indexnow.org/documentation

const ENDPOINT = 'https://api.indexnow.org/indexnow';
const PING_EVERY_MS = 24 * 60 * 60 * 1000;

// An IndexNow key is 8-128 chars, hex-ish (a-z, 0-9, dashes allowed).
export function indexNowKey() {
  const k = (process.env.INDEXNOW_KEY || '').trim();
  return /^[A-Za-z0-9-]{8,128}$/.test(k) ? k : '';
}

// POST the URL list. Returns the HTTP status, or 0 on network/timeout error.
export async function submitIndexNow(baseUrl, key, urls) {
  const host = new URL(baseUrl).host;
  const body = JSON.stringify({
    host,
    key,
    keyLocation: `${baseUrl}/${key}.txt`,
    urlList: urls,
  });
  try {
    const res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    return res.status;
  } catch {
    return 0;
  }
}

// Ping at most once per day, only when a key is set and we're on a public https
// origin. State is kept in the meta table so container restarts don't re-spam.
export async function maybePingIndexNow({ baseUrl, urls, getMeta, setMeta }) {
  const key = indexNowKey();
  if (!key) return { skipped: 'no INDEXNOW_KEY' };
  if (!/^https:\/\//i.test(baseUrl)) return { skipped: 'BASE_URL is not https' };

  const last = Number(getMeta('indexnow_last') || 0);
  if (Date.now() - last < PING_EVERY_MS) return { skipped: 'pinged < 24h ago' };

  const status = await submitIndexNow(baseUrl, key, urls);
  if (status >= 200 && status < 300) {
    setMeta('indexnow_last', Date.now());
    return { status, ok: true };
  }
  return { status, ok: false };
}
