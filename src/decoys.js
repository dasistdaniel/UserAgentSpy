// Passive decoys for common vulnerability-scanner probes. OFF by default
// (FAKE_ENDPOINTS env). Each returns a plausible-looking but entirely fake 200,
// so a scanner marks a "hit" and comes back with its second-stage payloads —
// which is exactly the bot behaviour this site exists to observe.
//
// Nothing here accepts input, has a working form, or collects anything. All
// values are obvious junk. Every hit is logged with source = 'decoy'.

const page = (title, note) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>` +
  `<body><p>${note}</p></body></html>\n`;

const DECOYS = new Map([
  ['/wp-login.php', {
    type: 'text/html; charset=utf-8',
    body: page('Log In', 'WordPress &rsaquo; please log in. <!-- wp-login wp-content wp-includes -->'),
  }],
  ['/wp-admin/', {
    type: 'text/html; charset=utf-8',
    body: page('Dashboard', 'You do not have sufficient permissions to access this page. <!-- wordpress -->'),
  }],
  ['/xmlrpc.php', {
    type: 'text/xml; charset=utf-8',
    body: '<?xml version="1.0"?><methodResponse><params><param><value>' +
      '<string>XML-RPC server accepts POST requests only.</string>' +
      '</value></param></params></methodResponse>\n',
  }],
  ['/.env', {
    type: 'text/plain; charset=utf-8',
    body:
      'APP_NAME=Laravel\nAPP_ENV=production\nAPP_DEBUG=false\n' +
      'APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' +
      'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=app\nDB_USERNAME=app\n' +
      'DB_PASSWORD=this-is-a-honeypot-not-a-real-password\n',
  }],
  ['/.git/config', {
    type: 'text/plain; charset=utf-8',
    body:
      '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n' +
      '[remote "origin"]\n\turl = https://example.invalid/app.git\n',
  }],
  ['/phpinfo.php', {
    type: 'text/html; charset=utf-8',
    body: page('phpinfo()', 'PHP Version 8.2.0 <!-- phpinfo() -->'),
  }],
  ['/server-status', {
    type: 'text/html; charset=utf-8',
    body: page('Apache Status', 'Apache Server Status &mdash; access disabled.'),
  }],
  ['/config.json', {
    type: 'application/json; charset=utf-8',
    body: '{"env":"production","debug":false,"secret":"honeypot-not-a-real-secret"}\n',
  }],
]);

export function decoyFor(pathname) {
  return DECOYS.get(pathname) || null;
}

export const decoyPaths = () => [...DECOYS.keys()];
