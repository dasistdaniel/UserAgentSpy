import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';

import { SPOOF_THRESHOLD } from './fingerprint.js';

let db;

// Raw per-request rows older than this are pruned daily (see pruneVisits).
// The user_agents catalogue is aggregate and kept forever. 0 or negative
// disables pruning. Override with VISITS_RETENTION_DAYS.
const RETENTION_DAYS = Math.floor(Number(process.env.VISITS_RETENTION_DAYS ?? 90));

export function initDb(path) {
  mkdirSync(dirname(path), { recursive: true });
  db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA auto_vacuum = INCREMENTAL;

    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS visits (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      ts              TEXT    NOT NULL,
      ua              TEXT    NOT NULL,
      ua_hash         TEXT    NOT NULL,
      path            TEXT    NOT NULL,
      method          TEXT    NOT NULL,
      status          INTEGER NOT NULL,
      referer         TEXT,
      accept_language TEXT,
      ip_hash         TEXT,
      is_bot          INTEGER NOT NULL,
      bot_name        TEXT,
      browser         TEXT,
      browser_version TEXT,
      os              TEXT,
      device          TEXT,
      source          TEXT    NOT NULL,
      http_version    TEXT,
      client_hints    INTEGER NOT NULL DEFAULT 0,
      spoof_score     INTEGER NOT NULL DEFAULT 0,
      spoof_reasons   TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_visits_ts      ON visits(ts);
    CREATE INDEX IF NOT EXISTS idx_visits_ua_hash ON visits(ua_hash);
    CREATE INDEX IF NOT EXISTS idx_visits_is_bot  ON visits(is_bot);

    CREATE TABLE IF NOT EXISTS user_agents (
      ua_hash    TEXT PRIMARY KEY,
      ua         TEXT    NOT NULL,
      first_seen TEXT    NOT NULL,
      last_seen  TEXT    NOT NULL,
      hits       INTEGER NOT NULL DEFAULT 0,
      is_bot     INTEGER NOT NULL,
      bot_name   TEXT,
      browser    TEXT,
      os         TEXT,
      device     TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ua_hits       ON user_agents(hits DESC);
    CREATE INDEX IF NOT EXISTS idx_ua_first_seen ON user_agents(first_seen DESC);
  `);

  // Migrate DBs created before the fingerprint columns existed.
  const visitCols = db.prepare('PRAGMA table_info(visits)').all().map((c) => c.name);
  const addCol = (name, def) => {
    if (!visitCols.includes(name)) db.exec(`ALTER TABLE visits ADD COLUMN ${name} ${def}`);
  };
  addCol('http_version', 'TEXT');
  addCol('client_hints', 'INTEGER NOT NULL DEFAULT 0');
  addCol('spoof_score', 'INTEGER NOT NULL DEFAULT 0');
  addCol('spoof_reasons', 'TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS idx_visits_spoof ON visits(spoof_score)');

  if (!db.prepare('SELECT 1 FROM meta WHERE key = ?').get('salt')) {
    db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run(
      'salt',
      crypto.randomBytes(32).toString('hex'),
    );
  }
  return db;
}

export function getSalt() {
  return db.prepare('SELECT value FROM meta WHERE key = ?').get('salt').value;
}

export function getMeta(key) {
  return db.prepare('SELECT value FROM meta WHERE key = ?').get(key)?.value ?? null;
}

export function setMeta(key, value) {
  db.prepare(
    `INSERT INTO meta (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).run(key, String(value));
}

const uaHashOf = (ua) =>
  crypto.createHash('sha256').update(ua || '').digest('hex').slice(0, 32);

export function recordVisit(v) {
  const uaHash = uaHashOf(v.ua);
  const p = v.parsed;
  const fp = v.fp || {};
  const bot = p.isBot ? 1 : 0;

  db.prepare(
    `INSERT INTO visits
       (ts, ua, ua_hash, path, method, status, referer, accept_language, ip_hash,
        is_bot, bot_name, browser, browser_version, os, device, source,
        http_version, client_hints, spoof_score, spoof_reasons)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    v.ts, v.ua || '', uaHash, v.path, v.method, v.status,
    v.referer || null, v.acceptLanguage || null, v.ipHash || null,
    bot, p.botName || null, p.browser || null, p.browserVersion || null,
    p.os || null, p.device || null, v.source,
    fp.httpVersion || null, fp.clientHints ? 1 : 0, fp.spoofScore || 0,
    fp.codes && fp.codes.length ? fp.codes.join(',') : null,
  );

  const changed = db.prepare(
    'UPDATE user_agents SET last_seen = ?, hits = hits + 1 WHERE ua_hash = ?',
  ).run(v.ts, uaHash).changes;

  if (changed === 0) {
    db.prepare(
      `INSERT INTO user_agents
         (ua_hash, ua, first_seen, last_seen, hits, is_bot, bot_name, browser, os, device)
       VALUES (?,?,?,?,1,?,?,?,?,?)`,
    ).run(
      uaHash, v.ua || '', v.ts, v.ts, bot, p.botName || null,
      p.browser || null, p.os || null, p.device || null,
    );
  }
}

// Newest distinct user-agents, most-recently-first-seen first. Backs /feed.xml.
export function recentUserAgents(limit = 50) {
  return db
    .prepare(
      `SELECT ua_hash, ua, first_seen, last_seen, hits, is_bot, bot_name, browser, os, device
       FROM user_agents ORDER BY first_seen DESC LIMIT ?`,
    )
    .all(Math.min(Math.max(1, limit | 0), 200));
}

// Everything known about one user-agent (by ua_hash). Returns null if unseen.
// After retention pruning the per-request rows age out but the catalogue row
// stays, so `recent`/`daily`/`paths` may be empty while `meta` is still present.
export function getUserAgentDetail(hash) {
  const meta = db
    .prepare(
      `SELECT ua_hash, ua, first_seen, last_seen, hits, is_bot, bot_name, browser, os, device
       FROM user_agents WHERE ua_hash = ?`,
    )
    .get(hash);
  if (!meta) return null;

  const one = (sql) => db.prepare(sql).get(hash);
  const all = (sql) => db.prepare(sql).all(hash);

  const agg = one(`
    SELECT COUNT(*) AS logged,
           MAX(spoof_score) AS max_spoof,
           MIN(ts) AS retained_from,
           SUM(CASE WHEN source = 'honeypot' THEN 1 ELSE 0 END) AS honeypot_hits,
           SUM(CASE WHEN source = 'decoy'    THEN 1 ELSE 0 END) AS decoy_hits,
           SUM(CASE WHEN client_hints = 1    THEN 1 ELSE 0 END) AS client_hint_hits
    FROM visits WHERE ua_hash = ?`);

  const trapPaths = all(
    `SELECT DISTINCT path FROM visits WHERE ua_hash = ? AND source = 'honeypot'`,
  );
  const trapDepth = trapPaths.reduce((m, r) => {
    const d = parseInt(r.path.split('/')[2], 10);
    return Number.isFinite(d) && d > m ? d : m;
  }, 0);

  const worst = one(`
    SELECT spoof_score, spoof_reasons FROM visits
    WHERE ua_hash = ? AND spoof_score > 0
    ORDER BY spoof_score DESC, ts DESC LIMIT 1`);

  const httpVersions = all(`
    SELECT COALESCE(http_version, '?') AS name, COUNT(*) AS c
    FROM visits WHERE ua_hash = ? GROUP BY name ORDER BY c DESC`);

  return {
    meta,
    agg,
    trapDepth,
    worst,
    httpVersions,
    daily: all(`
      SELECT substr(ts,1,10) AS day, COUNT(*) AS c
      FROM visits WHERE ua_hash = ? AND ts >= datetime('now','-30 day')
      GROUP BY day ORDER BY day`),
    paths: all(`
      SELECT path, COUNT(*) AS c, MAX(status) AS status,
             SUM(CASE WHEN status = 404 THEN 1 ELSE 0 END) AS notfound
      FROM visits WHERE ua_hash = ? GROUP BY path ORDER BY c DESC LIMIT 30`),
    recent: all(`
      SELECT ts, method, path, status, source, referer, spoof_score
      FROM visits WHERE ua_hash = ? ORDER BY ts DESC LIMIT 100`),
  };
}

// Short-lived cache: /stats auto-refreshes every 30 s and scrapers hammer
// /api/stats, so without this each hit would run ~10 aggregate queries. A few
// seconds of staleness on a dashboard is fine; TTL wins over write-invalidation
// because under a bot flood we specifically want the cache to hold.
const STATS_TTL_MS = 8000;
const statsCache = new Map(); // filter -> { at, data }

// filter: 'all' | 'bots' | 'humans' — narrows every per-visit / per-UA panel.
// The totals block always stays global (it's the overview).
export function getStats(filter = 'all') {
  const key = filter === 'bots' || filter === 'humans' ? filter : 'all';
  const hit = statsCache.get(key);
  if (hit && Date.now() - hit.at < STATS_TTL_MS) return hit.data;

  const data = computeStats(key);
  statsCache.set(key, { at: Date.now(), data });
  return data;
}

function computeStats(filter) {
  const all = (sql, ...a) => db.prepare(sql).all(...a);
  const one = (sql, ...a) => db.prepare(sql).get(...a);

  const bot = filter === 'bots' ? 1 : filter === 'humans' ? 0 : null;
  const vWhere = bot === null ? '' : `WHERE is_bot = ${bot}`;
  const vAnd = bot === null ? '' : `AND is_bot = ${bot}`;

  const totals = one(`
    SELECT
      (SELECT COUNT(*) FROM visits)                                   AS visits,
      (SELECT COUNT(*) FROM user_agents)                              AS uas,
      (SELECT COUNT(*) FROM visits      WHERE is_bot = 1)             AS bot_visits,
      (SELECT COUNT(*) FROM user_agents WHERE is_bot = 1)             AS bot_uas,
      (SELECT COUNT(*) FROM visits WHERE source = 'honeypot')         AS honeypot_hits,
      (SELECT COUNT(*) FROM visits WHERE source = 'decoy')            AS decoy_hits,
      (SELECT COUNT(*) FROM visits WHERE ts >= datetime('now','-1 day'))  AS last24h,
      (SELECT COUNT(*) FROM visits WHERE ts >= datetime('now','-7 day'))  AS last7d,
      (SELECT COUNT(*) FROM visits WHERE spoof_score >= ${SPOOF_THRESHOLD} AND is_bot = 0)
                                                                     AS spoofed_visits,
      (SELECT COUNT(DISTINCT ua_hash) FROM visits
         WHERE spoof_score >= ${SPOOF_THRESHOLD} AND is_bot = 0)      AS spoofed_uas
  `);

  // Client-Hints adoption among visits that claim a Chromium browser.
  const clientHints = one(`
    SELECT
      COUNT(*)                                  AS chromium_visits,
      SUM(CASE WHEN client_hints = 1 THEN 1 ELSE 0 END) AS with_hints
    FROM visits
    WHERE is_bot = 0
      AND browser IN ('Chrome','Microsoft Edge','Opera','Vivaldi',
                      'Samsung Internet','Yandex Browser','UC Browser')
  `);

  return {
    generatedAt: new Date().toISOString(),
    filter,
    totals,
    clientHints,
    spoofedUserAgents: all(`
      SELECT ua_hash, ua, browser, browser_version AS version,
             COUNT(*) AS c, MAX(spoof_score) AS score,
             MAX(spoof_reasons) AS reasons, MAX(ts) AS last_seen
      FROM visits
      WHERE spoof_score >= ${SPOOF_THRESHOLD} AND is_bot = 0
      GROUP BY ua_hash ORDER BY c DESC, score DESC LIMIT 15`),
    topUserAgents: all(`
      SELECT ua_hash, ua, hits, is_bot, bot_name, browser, os, device, last_seen
      FROM user_agents ${vWhere} ORDER BY hits DESC, last_seen DESC LIMIT 30`),
    newestUserAgents: all(`
      SELECT ua_hash, ua, first_seen, is_bot, bot_name, browser, os
      FROM user_agents ${vWhere} ORDER BY first_seen DESC LIMIT 15`),
    topBots: all(`
      SELECT COALESCE(NULLIF(bot_name,''), ua) AS name, COUNT(*) AS c
      FROM visits WHERE is_bot = 1
      GROUP BY name ORDER BY c DESC LIMIT 20`),
    browsers: all(`
      SELECT COALESCE(browser,'Unknown') AS name, COUNT(*) AS c
      FROM visits ${vWhere} GROUP BY name ORDER BY c DESC LIMIT 12`),
    oses: all(`
      SELECT COALESCE(os,'Unknown') AS name, COUNT(*) AS c
      FROM visits ${vWhere} GROUP BY name ORDER BY c DESC LIMIT 12`),
    devices: all(`
      SELECT COALESCE(device,'unknown') AS name, COUNT(*) AS c
      FROM visits ${vWhere} GROUP BY name ORDER BY c DESC`),
    topPaths: all(`
      SELECT path, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits ${vWhere} GROUP BY path ORDER BY c DESC LIMIT 20`),
    statusCodes: all(`
      SELECT status, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits ${vWhere} GROUP BY status ORDER BY c DESC`),
    notFoundPaths: all(`
      SELECT path, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits WHERE status = 404 ${vAnd}
      GROUP BY path ORDER BY c DESC LIMIT 20`),
    decoyPaths: all(`
      SELECT path, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits WHERE source = 'decoy' ${vAnd}
      GROUP BY path ORDER BY c DESC LIMIT 20`),
    daily: all(`
      SELECT substr(ts,1,10) AS day, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits WHERE ts >= datetime('now','-30 day') ${vAnd}
      GROUP BY day ORDER BY day`),
  };
}

// Delete raw visit rows past the retention window, then hand the freed pages
// back to the OS. Cheap enough to run on startup and once a day. Returns the
// number of rows deleted, or null when pruning is disabled.
export function pruneVisits() {
  if (!Number.isFinite(RETENTION_DAYS) || RETENTION_DAYS <= 0) return null;

  const deleted = db
    .prepare(`DELETE FROM visits WHERE ts < datetime('now', ?)`)
    .run(`-${RETENTION_DAYS} days`).changes;

  if (deleted > 0) {
    db.exec('PRAGMA incremental_vacuum');
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    statsCache.clear();
  }
  return deleted;
}

export const retentionDays = () => (RETENTION_DAYS > 0 ? RETENTION_DAYS : 0);

export function closeDb() {
  try {
    db?.close();
  } catch {
    /* ignore */
  }
}
