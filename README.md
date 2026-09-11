# useragents.spy

A tiny website that captures the **User-Agent** of every visitor — human or bot —
shows it back to them, stores it, and builds live statistics about who (and what)
crawls the web.

Target deployment: `https://useragents.nichtregistriert.de` (Docker on a VPS).

## What it does

| Route | Purpose |
| --- | --- |
| `GET /` | Shows your raw User-Agent + what the server parsed from it (browser, OS, device, bot?) **plus a header fingerprint** — whether `Accept`, `Accept-Encoding`, `Sec-Fetch-*`, `Sec-CH-UA` and the HTTP version match the browser the UA claims to be. Records the visit. |
| `GET /stats` | Live dashboard: totals, bot vs human, spoofed-browser hits, top user-agents, header-fingerprint mismatches, browsers, OSes, devices, probed paths, response status codes, top 404s, 30-day timeline, newest UAs. Auto-refreshes every 30 s. `?filter=bots` / `?filter=humans` narrows every panel below the totals. |
| `GET /stats/ua/<hash>` | Detail page for one **bot/crawler** user-agent (by its `ua_hash`): parsed info, first/last seen, honeypot depth walked, decoy hits, fingerprint verdict, per-day activity, paths requested, recent requests. 404s for human UAs — see [Data & privacy](#data--privacy). Linked from bot rows in the `/stats` tables and from the feed. |
| `GET /api/stats` | Same data as JSON (CORS-open). Honors the same `?filter=`. |
| `GET /feed.xml` | Atom feed of the 50 newest **bot/crawler** user-agents (one `<entry>` each, linking to its detail page). Advertised via `<link rel="alternate">` in every page head. |
| `GET /llms.txt` | [llmstxt.org](https://llmstxt.org/) map of the site for LLM crawlers — blurb + links to the pages and data. Pointed at from `robots.txt`. |
| `GET /robots.txt` | Allows everything, points crawlers at the sitemap, `/llms.txt` and `/datenschutz`. |
| `GET /sitemap.xml` | Lists `/`, `/stats`, `/datenschutz`, and the 200 most recent **bot** `/stats/ua/<hash>` pages. |
| `GET /datenschutz` | The privacy policy — see [Data & privacy](#data--privacy). |
| `GET /trap/<depth>/<token>` | Honeypot "crawler maze" — every page links to a few deeper ones (bounded at depth 8). Hits are logged with `source = honeypot`. |
| `GET /wp-login.php`, `/.env`, … | **Only when `FAKE_ENDPOINTS` is on:** a fake `200` for common scanner probes instead of a `404`, logged with `source = decoy` (see below). |
| anything else | Logged as a 404 (bot probes like `/wp-login.php` are valuable data). |

Every request except `/api/stats`, `/healthz`, `/favicon.ico`, and requests sending
`DNT: 1` / `Sec-GPC: 1`, is written to the database.

## Attracting crawlers ("Standard + Honeypot")

- `robots.txt` explicitly allows all agents and advertises the sitemap.
- `sitemap.xml` is served for search engines.
- The landing page contains **hidden honeypot links** (`<div>` off-screen,
  `aria-hidden`, `rel="nofollow"`) that lead into `/trap/...`. Real users never see
  them; crawlers that ignore `nofollow` walk the maze and identify themselves.
- After deploying, submit the domain to: Google Search Console, Bing Webmaster
  Tools, and a few "what's my user agent" / free-tools link directories. Backlinks
  are what actually bring the long tail of crawlers.

### Decoy endpoints (`FAKE_ENDPOINTS`, off by default)

Set `FAKE_ENDPOINTS=true` and a handful of classic vulnerability-scanner targets
(`/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, `/.env`, `/.git/config`,
`/phpinfo.php`, `/server-status`, `/config.json`) answer with a **plausible-looking
but entirely fake `200`** instead of a `404`. Scanners often act in stages — a
`404` ends the probe, a `200` reads as a hit and brings the bot back with its
second-stage payloads, which is exactly the behaviour worth observing. The fake
responses accept no input, have no working form, and contain only obvious junk;
each hit is logged with `source = decoy` and shown on `/stats` in its own panel.
This is deliberately more aggressive than the default "Standard + Honeypot" stance,
hence opt-in. Decoys are defined in `src/decoys.js`.

### IndexNow (Bing + Yandex push)

Set `INDEXNOW_KEY` to a random hex string (`openssl rand -hex 16`). On startup —
at most once per 24 h, and only when `BASE_URL` is `https://…` — the server POSTs
`/` and `/stats` to `https://api.indexnow.org/indexnow`, and serves the ownership
file at `https://useragents.nichtregistriert.de/<key>.txt`. The last-ping
timestamp lives in the `meta` table, so container restarts don't re-spam.
Leave the key empty to disable the feature entirely.

### Google Search Console (file verification)

When you add the property in Search Console, pick the HTML-file method and set
`GOOGLE_VERIFY` to the token from the `googleXXXX.html` file Google gives you
(the `.html` suffix is optional). The server then answers
`GET /googleXXXX.html` with `google-site-verification: googleXXXX.html`.
After it verifies, submit `https://useragents.nichtregistriert.de/sitemap.xml`.

## Data & privacy

The full, human-readable policy is served live at `/datenschutz` (linked from
every page footer) and is generated from the same constants described here, so
it can't drift out of sync with `VISITS_RETENTION_DAYS`.

- Stored per request: timestamp, raw UA string, path, method, status,
  **referer — origin only**, never the path or query string (a Referer can carry
  a search query or a token that belongs to someone else's site), `Accept-Language`,
  parsed browser/OS/device, bot flag + guessed bot name, HTTP version, whether
  Client Hints were sent, and a **spoof score** with the list of failed header
  checks (see below).
- **IP addresses are never stored.** Only a truncated SHA-256 of
  `secret_salt : yyyy-mm-dd : ip` is kept, so the same visitor can be counted once
  per day without the address being recoverable. The salt is random per database
  (in the `meta` table).
- No cookies, no JS trackers, no third-party requests, no accounts.
- **`DNT: 1` / `Sec-GPC: 1` is honored as an opt-out**: the request is still served
  normally, but nothing is written to the database — no row, no catalogue entry.
- **Individually-identifiable public pages exist only for bots.** `/stats/ua/<hash>`,
  the Atom feed, and the sitemap only ever include entries where `is_bot = 1`.
  A human visitor is reflected solely in the aggregate counts on `/stats` — never
  as a linkable page with its own timestamped request history. This is the main
  design choice that keeps the site's rich, indexed "crawler observatory" content
  from turning into a public log of an identifiable person's browsing activity.
- **Retention:** raw per-request rows are pruned once a day (and on startup) once
  they pass `VISITS_RETENTION_DAYS` (default 90); set it to `0` to keep everything.
  Once a **human** visitor's browser has been quiet for that same window, its
  `user_agents` catalogue row is deleted too. **Bot** catalogue rows (first/last
  seen, hit count) are kept forever — that long-term "who crawls us" record is
  the project's actual purpose, and automated agents aren't people whose data has
  to age out under GDPR storage-limitation rules. Freed pages are returned to the
  OS via incremental vacuum; a full `VACUUM` on an existing DB is a one-time manual
  step if you want the file itself to shrink immediately.

### GDPR

The above is a solid technical baseline (data minimization, storage limitation,
an honored opt-out signal, no public exposure of identifiable individuals).
`/datenschutz` (`renderPrivacy` in `src/views.js`) names the controller (Art. 13
GDPR: name + e-mail — no postal address, which isn't strictly required by the
GDPR text) and states that this is a private, non-commercial project with no
separate **Impressum** (German DDG §5 "Anbieterkennzeichnung"). Whether that
private-use framing would hold up is fact-dependent and ultimately the
operator's call, not something either this README or an AI assistant can
certify — none of this is legal advice.

## Header fingerprint & spoof detection

The UA string is trivially forged, so `src/fingerprint.js` also looks at headers
a *real* browser sends fairly rigidly. When a request's UA claims a mainstream
browser (Chrome, Firefox, Safari, Edge…) each of these adds to a **spoof score**:

| Signal | Weight |
| --- | --- |
| no `Accept` header | 3 |
| `Accept: */*` (browsers send `text/html,…` for navigations) | 2 |
| no `Accept-Encoding` header | 3 |
| `Accept-Encoding` with no known compression | 2 |
| no `Accept-Language` header | 1 |
| HTTP/1.0 request | 2 |
| no `Sec-Fetch-*` headers | 2 |
| Chromium ≥ 90 without `Sec-CH-UA` | 2 |
| `Connection: close` on HTTP/1.1 | 1 |
| `From` header set (crawler contact-address convention) | 4 |

Score ≥ 4 (i.e. at least two independent signals) marks the visit as a
**suspected spoofed browser** on `/stats`. It is deliberately *separate* from the
UA-regex `is_bot` flag — no single missing header is proof (a proxy can strip
one, an old browser lacks `Sec-Fetch`), so the reasons are always shown so a
human can judge. **If your reverse proxy strips these headers, every browser
visit will be flagged** — check `/` in a real browser after deploying.

## Run locally

Requires **Node.js ≥ 22.5** (uses the built-in `node:sqlite` — no npm packages).

```bash
PORT=7060 npm start   # http://localhost:7060
npm run dev           # same, with --watch
```

Env vars: `PORT` (7060), `HOST` (0.0.0.0), `DB_PATH` (./data/app.db),
`BASE_URL` (http://localhost:PORT), `TRUST_PROXY` (false),
`TRAP_SECRET` (changes the maze token space),
`INDEXNOW_KEY` (empty — see below), `GOOGLE_VERIFY` (empty — see below),
`VISITS_RETENTION_DAYS` (90 — see below), `FAKE_ENDPOINTS` (off — see below).

## Deploy with Docker

On the VPS:

```bash
git clone <this-repo> useragents-spy && cd useragents-spy
docker compose up -d --build
```

The container listens on port `7060` and stores the SQLite DB in the named
volume `uaspy-data` (`/data/app.db`).

`docker-compose.yml` currently ships a **direct-test** configuration: port
`7060` on all interfaces, `TRUST_PROXY=false`,
`BASE_URL=http://192.168.178.20:7060`. Test with
`curl http://<host>:7060/` and open `/stats` in a browser.

When the domain goes live, edit `docker-compose.yml`:

- `ports:` → `"127.0.0.1:7060:7060"`
- `TRUST_PROXY` → `"true"`
- `BASE_URL` → `https://useragents.nichtregistriert.de`

### Reverse proxy

Point `useragents.nichtregistriert.de` at `127.0.0.1:7060` and terminate TLS there.

**Caddy** (`/etc/caddy/Caddyfile`):

```
useragents.nichtregistriert.de {
    reverse_proxy 127.0.0.1:7060
}
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name useragents.nichtregistriert.de;
    # ssl_certificate ... (certbot)

    location / {
        proxy_pass http://127.0.0.1:7060;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Traefik** (compose labels) — add to the `app` service and attach your proxy network:

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.uaspy.rule=Host(`useragents.nichtregistriert.de`)
      - traefik.http.routers.uaspy.tls.certresolver=le
      - traefik.http.services.uaspy.loadbalancer.server.port=7060
```

(Then drop the `ports:` mapping and put the container on the Traefik network.)

### Updating

```bash
git pull && docker compose up -d --build
```

The database survives in the volume. Back it up with:

```bash
docker run --rm -v uaspy-data:/data -v "$PWD":/backup alpine \
  sh -c 'cp /data/app.db* /backup/'
```

## Project layout

```
src/
  server.js      HTTP server + routing + request logging
  db.js          node:sqlite schema, recordVisit(), getStats(), retention
  feed.js        Atom feed of the newest user-agents
  decoys.js      fake 200s for scanner probes (opt-in via FAKE_ENDPOINTS)
  ua.js          dependency-free User-Agent parser + bot detection
  fingerprint.js header-fingerprint analysis + spoof score
  views.js       HTML rendering (inline CSS, dark theme)
  honeypot.js    bounded crawler-maze link generation
  indexnow.js    IndexNow ping (Bing + Yandex)
Dockerfile          node:24-alpine, runs as non-root
docker-compose.yml  port 7060, named volume for the DB
```

## License

MIT
