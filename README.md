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
| `GET /api/stats` | Same data as JSON (CORS-open). Honors the same `?filter=`. |
| `GET /feed.xml` | Atom feed of the 50 newest distinct user-agents (one `<entry>` each). Advertised via `<link rel="alternate">` in every page head. |
| `GET /robots.txt` | Allows everything, points crawlers at the sitemap. |
| `GET /sitemap.xml` | Lists `/` and `/stats`. |
| `GET /trap/<depth>/<token>` | Honeypot "crawler maze" — every page links to a few deeper ones (bounded at depth 8). Hits are logged with `source = honeypot`. |
| anything else | Logged as a 404 (bot probes like `/wp-login.php` are valuable data). |

Every request except `/api/stats`, `/healthz` and `/favicon.ico` is written to the
database.

## Attracting crawlers ("Standard + Honeypot")

- `robots.txt` explicitly allows all agents and advertises the sitemap.
- `sitemap.xml` is served for search engines.
- The landing page contains **hidden honeypot links** (`<div>` off-screen,
  `aria-hidden`, `rel="nofollow"`) that lead into `/trap/...`. Real users never see
  them; crawlers that ignore `nofollow` walk the maze and identify themselves.
- After deploying, submit the domain to: Google Search Console, Bing Webmaster
  Tools, and a few "what's my user agent" / free-tools link directories. Backlinks
  are what actually bring the long tail of crawlers.

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

- Stored per request: timestamp, raw UA string, path, method, status, referer,
  `Accept-Language`, parsed browser/OS/device, bot flag + guessed bot name,
  HTTP version, whether Client Hints were sent, and a **spoof score** with the
  list of failed header checks (see below).
- **IP addresses are never stored.** Only a truncated SHA-256 of
  `secret_salt : yyyy-mm-dd : ip` is kept, so the same visitor can be counted once
  per day without the address being recoverable. The salt is random per database
  (in the `meta` table).
- No cookies, no JS trackers, no third-party requests.
- **Retention:** raw per-request rows are pruned once a day (and on startup) once
  they pass `VISITS_RETENTION_DAYS` (default 90); set it to `0` to keep everything.
  The `user_agents` catalogue (one row per distinct UA, with first/last seen and
  hit count) is kept forever, so long-term "who crawls us" data survives — only
  the per-hit path/referer/timeline detail ages out. Freed pages are returned to
  the OS via incremental vacuum; a full `VACUUM` on an existing DB is a one-time
  manual step if you want the file itself to shrink immediately.

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
`VISITS_RETENTION_DAYS` (90 — see below).

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
