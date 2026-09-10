// Header-fingerprint analysis: does the request look like it came from the
// browser its User-Agent claims? Real browsers send a fairly rigid set of
// headers (Accept, Accept-Encoding, Sec-Fetch-*, Client Hints on Chromium…);
// UA-spoofing scrapers usually don't bother. None of these signals is proof on
// its own — a proxy can strip a header, an old browser omits Sec-Fetch — so we
// add up weights and flag only when several independent signals stack up.

// code -> [weight, human-readable explanation]
export const SIGNALS = {
  no_accept: [3, 'no Accept header'],
  accept_star: [2, 'Accept is */* (browsers send text/html,… for navigations)'],
  no_accept_encoding: [3, 'no Accept-Encoding header'],
  weak_accept_encoding: [2, 'Accept-Encoding advertises no known compression'],
  no_accept_language: [1, 'no Accept-Language header'],
  http_1_0: [2, 'HTTP/1.0 request'],
  no_sec_fetch: [2, 'no Sec-Fetch-* headers'],
  no_client_hints: [2, 'Chromium ≥ 90 but no Sec-CH-UA header'],
  connection_close: [1, 'Connection: close on an HTTP/1.1 request'],
  from_header: [4, 'From header set (a crawler contact-address convention)'],
};

export const SPOOF_THRESHOLD = 4;

const CHROMIUM = new Set([
  'Chrome', 'Microsoft Edge', 'Opera', 'Vivaldi', 'Samsung Internet',
  'Yandex Browser', 'UC Browser',
]);
const REAL_BROWSERS = new Set([...CHROMIUM, 'Firefox', 'Safari']);

export function analyzeRequest(req, parsed) {
  const h = req.headers || {};
  const httpVersion = req.httpVersion || '1.1';
  const accept = h['accept'] || '';
  const acceptEncoding = h['accept-encoding'] || '';
  const sentClientHints = 'sec-ch-ua' in h;
  const sentSecFetch =
    'sec-fetch-mode' in h || 'sec-fetch-dest' in h || 'sec-fetch-site' in h;
  const claimsBrowser = !parsed.isBot && REAL_BROWSERS.has(parsed.browser);

  const codes = [];
  if (claimsBrowser) {
    if (!accept) codes.push('no_accept');
    else if (accept.trim() === '*/*') codes.push('accept_star');

    if (!acceptEncoding) codes.push('no_accept_encoding');
    else if (!/\b(gzip|br|deflate|zstd|compress)\b/i.test(acceptEncoding))
      codes.push('weak_accept_encoding');

    if (!h['accept-language']) codes.push('no_accept_language');
    if (httpVersion === '1.0') codes.push('http_1_0');
    if (!sentSecFetch) codes.push('no_sec_fetch');

    const major = parseInt(parsed.browserVersion, 10);
    if (CHROMIUM.has(parsed.browser) && major >= 90 && !sentClientHints)
      codes.push('no_client_hints');

    if ((h['connection'] || '').toLowerCase().includes('close') && httpVersion === '1.1')
      codes.push('connection_close');
  }
  if (h['from']) codes.push('from_header');

  const spoofScore = codes.reduce((s, c) => s + (SIGNALS[c]?.[0] ?? 1), 0);

  return {
    httpVersion,
    claimsBrowser,
    clientHints: sentClientHints,
    isChromium: CHROMIUM.has(parsed.browser),
    accept: accept || null,
    acceptEncoding: acceptEncoding || null,
    acceptLanguage: h['accept-language'] || null,
    secFetch: sentSecFetch
      ? ['site', 'mode', 'dest', 'user'].map((k) => h[`sec-fetch-${k}`] || '·').join(' / ')
      : null,
    secChUa: h['sec-ch-ua'] || null,
    spoofScore,
    spoofed: spoofScore >= SPOOF_THRESHOLD,
    codes,
  };
}

export const explainCodes = (csv) =>
  (csv || '')
    .split(',')
    .filter(Boolean)
    .map((c) => SIGNALS[c]?.[1] || c);
