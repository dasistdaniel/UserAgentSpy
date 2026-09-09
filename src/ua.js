// Lightweight, dependency-free User-Agent parser.
// Goal: good-enough classification of browser / OS / device and robust bot detection.

// Strong bot signals: named crawlers, HTTP libraries, monitoring, scanners, and the
// generic "bot / crawler / spider" tokens. Also: a bare URL / e-mail in the UA string
// (polite crawlers advertise a contact address) — no real browser does that.
const BOT_RE = new RegExp(
  [
    'bot\\b', 'crawler', 'crawl(?:ing|er)?', 'spider', 'slurp', 'scraper', 'scrape',
    'https?://', '\\+http', 'www\\.', '(?:^|\\s)[\\w.-]+@[\\w.-]+\\.[a-z]{2,}',
    'feed(?:fetcher|ly|parser)', 'mediapartners', 'facebookexternalhit', 'facebot',
    'ia_archiver', 'archive\\.org', 'bingpreview', 'embedly', 'quora', 'outbrain',
    'pinterest', 'vkshare', 'w3c_validator', 'whatsapp', 'telegrambot', 'discordbot',
    'slackbot', 'twitterbot', 'linkedinbot', 'skypeuripreview', 'applebot', 'petalbot',
    'semrushbot', 'ahrefsbot', 'ahrefssiteaudit', 'mj12bot', 'dotbot', 'dataforseobot',
    'screaming ?frog', 'gptbot', 'oai-searchbot', 'chatgpt-user', 'ccbot', 'claudebot',
    'claude-web', 'anthropic-ai', 'perplexitybot', 'google-extended', 'googleother',
    'bytespider', 'amazonbot', 'yandex(?:bot|images|mobilebot)?', 'baiduspider', 'sogou',
    'exabot', 'exalead', 'duckduckbot', 'duckduckgo', 'seznambot', 'qwantify',
    'curl/', 'wget/', 'libcurl', 'python-requests', 'python-urllib', 'aiohttp', 'httpx/',
    'go-http-client', 'okhttp', 'apache-httpclient', 'jakarta', 'libwww-perl', 'axios/',
    'node-fetch', 'got \\(', 'scrapy', 'colly', 'guzzle', 'headlesschrome', 'phantomjs',
    'puppeteer', 'playwright', 'lighthouse', 'pingdom', 'uptimerobot', 'uptime-kuma',
    'statuscake', 'site24x7', 'gtmetrix', 'newrelicpinger', 'datadog', 'nuclei',
    'masscan', 'zgrab', 'censys', 'shodan', 'zmap', 'nmap', 'nikto', 'sqlmap', 'wpscan',
    'internet-?measurement', 'paloaltonetworks', 'expanse', 'l9explore', 'projectdiscovery',
  ].join('|'),
  'i',
);

function botName(ua) {
  let m = ua.match(/([A-Za-z0-9._-]*(?:bot|spider|crawler|slurp|scraper)[A-Za-z0-9._-]*)/i);
  if (m) return m[1];
  m = ua.match(/^([A-Za-z0-9._ -]+?)[/ ]\d/); // first token before a version number
  if (m) return m[1].trim();
  m = ua.match(/([a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s;)]*)?)/i); // a domain in the string
  if (m) return m[1];
  return ua.slice(0, 60);
}

const BROWSERS = [
  [/edg(?:a|ios)?\/([\d.]+)/i, 'Microsoft Edge'],
  [/opr\/([\d.]+)/i, 'Opera'],
  [/opera[ /]([\d.]+)/i, 'Opera'],
  [/vivaldi\/([\d.]+)/i, 'Vivaldi'],
  [/yabrowser\/([\d.]+)/i, 'Yandex Browser'],
  [/samsungbrowser\/([\d.]+)/i, 'Samsung Internet'],
  [/ucbrowser\/([\d.]+)/i, 'UC Browser'],
  [/firefox\/([\d.]+)/i, 'Firefox'],
  [/fxios\/([\d.]+)/i, 'Firefox'],
  [/(?:chrome|crios)\/([\d.]+)/i, 'Chrome'],
  [/version\/([\d.]+)(?:\s\w+)*\ssafari/i, 'Safari'],
  [/\bsafari\/([\d.]+)/i, 'Safari'],
  [/msie\s([\d.]+)/i, 'Internet Explorer'],
  [/trident.*?rv:([\d.]+)/i, 'Internet Explorer'],
  [/(?:^|\s)wget\/([\d.]+)/i, 'wget'],
  [/(?:^|\s)curl\/([\d.]+)/i, 'curl'],
];

function detectOS(ua) {
  let m;
  if (/windows nt 10/i.test(ua)) return 'Windows 10/11';
  if (/windows nt 6\.3/i.test(ua)) return 'Windows 8.1';
  if (/windows nt 6\.2/i.test(ua)) return 'Windows 8';
  if (/windows nt 6\.1/i.test(ua)) return 'Windows 7';
  if (/windows nt 5\.1/i.test(ua)) return 'Windows XP';
  if (/windows phone\s?([\d.]+)?/i.test(ua)) return 'Windows Phone';
  if (/windows nt/i.test(ua)) return 'Windows';
  if ((m = ua.match(/android[\s/]([\d.]+)/i))) return 'Android ' + m[1];
  if (/android/i.test(ua)) return 'Android';
  if ((m = ua.match(/(?:iphone|ipad|ipod).*?os\s([\d_]+)/i))) return 'iOS ' + m[1].replace(/_/g, '.');
  if (/cros/i.test(ua)) return 'ChromeOS';
  if ((m = ua.match(/mac os x\s([\d_.]+)/i))) return 'macOS ' + m[1].replace(/_/g, '.');
  if (/mac os x|macintosh/i.test(ua)) return 'macOS';
  if (/freebsd/i.test(ua)) return 'FreeBSD';
  if (/openbsd/i.test(ua)) return 'OpenBSD';
  if (/linux/i.test(ua)) return 'Linux';
  return 'Unknown';
}

function detectDevice(ua, isBot) {
  if (isBot) return 'bot';
  if (/ipad|(?:android(?!.*mobile))|tablet|kindle|silk|playbook/i.test(ua)) return 'tablet';
  if (/mobi|iphone|ipod|windows phone|blackberry|bb10|opera mini/i.test(ua)) return 'mobile';
  return 'desktop';
}

export function parseUA(uaRaw) {
  const ua = (uaRaw || '').trim();
  if (!ua) {
    return {
      isBot: true, // no UA header at all is a strong non-human signal
      botName: '(no user-agent)',
      browser: 'None',
      browserVersion: null,
      os: 'Unknown',
      device: 'bot',
      empty: true,
    };
  }

  const isBot = BOT_RE.test(ua);
  const out = {
    isBot,
    botName: isBot ? botName(ua) : null,
    browser: null,
    browserVersion: null,
    os: detectOS(ua),
    device: null,
    empty: false,
  };

  for (const [re, name] of BROWSERS) {
    const m = ua.match(re);
    if (m) {
      out.browser = name;
      out.browserVersion = m[1] || null;
      break;
    }
  }
  if (!out.browser) out.browser = isBot ? 'Bot / library' : 'Unknown';
  out.device = detectDevice(ua, isBot);
  return out;
}
