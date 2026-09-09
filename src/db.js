import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';

let db;

export function initDb(path) {
  mkdirSync(dirname(path), { recursive: true });
  db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;

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
      source          TEXT    NOT NULL
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
  const bot = p.isBot ? 1 : 0;

  db.prepare(
    `INSERT INTO visits
       (ts, ua, ua_hash, path, method, status, referer, accept_language, ip_hash,
        is_bot, bot_name, browser, browser_version, os, device, source)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    v.ts, v.ua || '', uaHash, v.path, v.method, v.status,
    v.referer || null, v.acceptLanguage || null, v.ipHash || null,
    bot, p.botName || null, p.browser || null, p.browserVersion || null,
    p.os || null, p.device || null, v.source,
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

export function getStats() {
  const all = (sql, ...a) => db.prepare(sql).all(...a);
  const one = (sql, ...a) => db.prepare(sql).get(...a);

  const totals = one(`
    SELECT
      (SELECT COUNT(*) FROM visits)                                   AS visits,
      (SELECT COUNT(*) FROM user_agents)                              AS uas,
      (SELECT COUNT(*) FROM visits      WHERE is_bot = 1)             AS bot_visits,
      (SELECT COUNT(*) FROM user_agents WHERE is_bot = 1)             AS bot_uas,
      (SELECT COUNT(*) FROM visits WHERE source = 'honeypot')         AS honeypot_hits,
      (SELECT COUNT(*) FROM visits WHERE ts >= datetime('now','-1 day'))  AS last24h,
      (SELECT COUNT(*) FROM visits WHERE ts >= datetime('now','-7 day'))  AS last7d
  `);

  return {
    generatedAt: new Date().toISOString(),
    totals,
    topUserAgents: all(`
      SELECT ua, hits, is_bot, bot_name, browser, os, device, last_seen
      FROM user_agents ORDER BY hits DESC, last_seen DESC LIMIT 30`),
    newestUserAgents: all(`
      SELECT ua, first_seen, is_bot, bot_name, browser, os
      FROM user_agents ORDER BY first_seen DESC LIMIT 15`),
    topBots: all(`
      SELECT COALESCE(NULLIF(bot_name,''), ua) AS name, COUNT(*) AS c
      FROM visits WHERE is_bot = 1
      GROUP BY name ORDER BY c DESC LIMIT 20`),
    browsers: all(`
      SELECT COALESCE(browser,'Unknown') AS name, COUNT(*) AS c
      FROM visits GROUP BY name ORDER BY c DESC LIMIT 12`),
    oses: all(`
      SELECT COALESCE(os,'Unknown') AS name, COUNT(*) AS c
      FROM visits GROUP BY name ORDER BY c DESC LIMIT 12`),
    devices: all(`
      SELECT COALESCE(device,'unknown') AS name, COUNT(*) AS c
      FROM visits GROUP BY name ORDER BY c DESC`),
    topPaths: all(`
      SELECT path, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits GROUP BY path ORDER BY c DESC LIMIT 20`),
    daily: all(`
      SELECT substr(ts,1,10) AS day, COUNT(*) AS c, SUM(is_bot) AS bots
      FROM visits WHERE ts >= datetime('now','-30 day')
      GROUP BY day ORDER BY day`),
  };
}

export function closeDb() {
  try {
    db?.close();
  } catch {
    /* ignore */
  }
}
