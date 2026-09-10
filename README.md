# useragents.spy

A tiny website that captures the **User-Agent** of every visitor — human or bot —
shows it back to them, stores it, and builds live statistics about who (and what)
crawls the web.

Target deployment: `https://useragents.nichtregistriert.de` (Docker on a VPS).

## What it does

| Route | Purpose |
| --- | --- |
| `GET /` | Shows your raw User-Agent + what the server parsed from it (browser, OS, device, bot?). Records the visit. |
| `GET /stats` | Live dashboard: totals, bot vs human, top user-agents, browsers, OSes, devices, probed paths, 30-day timeline, newest UAs. Auto-refreshes every 30 s. `?filter=bots` / `?filter=humans` narrows every panel below the totals. |
| `GET /api/stats` | Same data as JSON (CORS-open). Honors the same `?filter=`. |
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
  `Accept-Language`, parsed browser/OS/device, bot flag + guessed bot name.
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
  server.js    HTTP server + routing + request logging
  db.js        node:sqlite schema, recordVisit(), getStats()
  ua.js        dependency-free User-Agent parser + bot detection
  views.js     HTML rendering (inline CSS, dark theme)
  honeypot.js  bounded crawler-maze link generation
Dockerfile          node:24-alpine, runs as non-root
docker-compose.yml  port 7060, named volume for the DB
```

## License

MIT
