// Atom 1.0 feed of the newest distinct user-agents seen. Gives feed readers
// (and their bots — logged like everything else) a reason to poll.

const xml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
  }[c]));

// '2026-09-10 09:00:00' (stored UTC) -> RFC 3339 '2026-09-10T09:00:00Z'
const rfc3339 = (ts) => (ts ? ts.replace(' ', 'T') + 'Z' : new Date().toISOString());

function entryTitle(u) {
  const who = u.is_bot ? 'Bot' : 'Human';
  const name = u.bot_name || u.browser || 'unknown';
  return `${who}: ${name}${u.os && u.os !== 'Unknown' ? ` on ${u.os}` : ''}`;
}

export function renderAtom({ baseUrl, entries }) {
  const host = new URL(baseUrl).host;
  const updated = rfc3339(entries[0]?.first_seen);

  const items = entries
    .map((u) => {
      const content = [
        `First seen ${u.first_seen} UTC (last seen ${u.last_seen}, ${u.hits} hit${
          u.hits === 1 ? '' : 's'
        }).`,
        `Classification: ${u.is_bot ? 'bot' : 'human'}${
          u.bot_name ? ` (${u.bot_name})` : ''
        }.`,
        `Browser: ${u.browser || 'unknown'}. OS: ${u.os || 'unknown'}. Device: ${
          u.device || 'unknown'
        }.`,
        `User-Agent: ${u.ua || '(no User-Agent header sent)'}`,
      ].join('\n');

      return `  <entry>
    <title>${xml(entryTitle(u))}</title>
    <id>tag:${host},2026:ua/${xml(u.ua_hash)}</id>
    <updated>${rfc3339(u.first_seen)}</updated>
    <link href="${xml(baseUrl)}/stats/ua/${xml(u.ua_hash)}"/>
    <content type="text">${xml(content)}</content>
  </entry>`;
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>${xml(host)} — newest user-agents</title>
  <subtitle>Distinct User-Agent strings this site has seen, newest first.</subtitle>
  <id>${xml(baseUrl)}/feed.xml</id>
  <link rel="self" href="${xml(baseUrl)}/feed.xml"/>
  <link href="${xml(baseUrl)}/stats"/>
  <updated>${updated}</updated>
${items}
</feed>
`;
}
