// Syndication and discovery surfaces, INTEROP §7.
//
// Atom, RSS, a sitemap, an OpenSearch description and robots.txt. None of
// these needs a client that knows anything about Basalt, which is the point:
// a reader subscribes in NetNewsWire or Thunderbird, a crawler indexes a
// public vault, a browser adds the search engine.
//
// Every feed is still per-principal and `private, no-store`: a feed is a
// filtered view, not a publication, and an aggregator that shares its cache
// across users would otherwise do the leaking §12.5 forbids.

import { splitFrontmatter } from '../frontmatter.mjs';
import { Fault } from './core.mjs';

const xml = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&apos;')
  // Characters XML 1.0 cannot carry at all, rather than emitting a document
  // no parser will accept.
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');

const nodeUrl = (base, path) =>
  `${base}/api/v1/node/${path.split('/').map(encodeURIComponent).join('/')}`;

const iso = (v, fallback) => {
  const d = v ? new Date(v) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toISOString() : fallback;
};

const rfc822 = (v) => {
  const d = v ? new Date(v) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toUTCString() : new Date(0).toUTCString();
};

/** A plain-text summary: frontmatter gone, markdown knocked off, clipped. */
export function summarize(text, limit = 320) {
  if (!text) return '';
  const body = splitFrontmatter(text).body ?? '';
  const flat = body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/!?\[\[([^\]|#]+)(?:[#|][^\]]*)?\]\]/g, '$1')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[*_`>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return flat.length > limit ? flat.slice(0, limit - 1).trimEnd() + '…' : flat;
}

/** Entries for the syndication surfaces, with a summary where one is cheap. */
async function feedEntries(surface, principal, { limit }) {
  const rows = await surface.recent(principal, { limit, publishedOnly: true });
  return Promise.all(rows.map(async (e) => {
    let summary = '';
    if (e.kind === 'note') {
      try {
        const r = await surface.node(principal, e.path);
        summary = summarize(r.text);
      } catch (err) {
        if (!(err instanceof Fault)) throw err;  // a denial here is a race, not an error
      }
    }
    return { ...e, summary };
  }));
}

export async function atom(surface, principal, { base, limit = 20, now }) {
  const man = surface.manifest();
  const entries = await feedEntries(surface, principal, { limit });
  const updated = iso(entries[0]?.mtime, now);
  const out = ['<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    `  <id>urn:basalt:vault:${xml(man.vault.id)}</id>`,
    `  <title>${xml(man.vault.title ?? man.vault.id)}</title>`,
    `  <updated>${updated}</updated>`,
    `  <generator version="1">basalt</generator>`,
    `  <link rel="self" href="${xml(base + '/feed.atom')}"/>`,
    `  <link rel="alternate" type="application/json" href="${xml(base + '/api/v1/tree')}"/>`,
  ];
  for (const e of entries) {
    out.push('  <entry>',
      `    <id>urn:basalt:node:${xml(e.id)}</id>`,
      `    <title>${xml(e.title)}</title>`,
      `    <updated>${iso(e.mtime, updated)}</updated>`,
      `    <link rel="alternate" type="application/json" href="${xml(nodeUrl(base, e.path))}"/>`,
      `    <link rel="enclosure" type="${xml(e.kind === 'note' ? 'text/markdown' : 'application/octet-stream')}" href="${xml(base + '/api/v1/raw/' + e.path.split('/').map(encodeURIComponent).join('/'))}"/>`);
    for (const t of e.tags ?? []) out.push(`    <category term="${xml(t)}"/>`);
    if (e.summary) out.push(`    <summary type="text">${xml(e.summary)}</summary>`);
    out.push('  </entry>');
  }
  out.push('</feed>', '');
  return out.join('\n');
}

export async function rss(surface, principal, { base, limit = 20, now }) {
  const man = surface.manifest();
  const entries = await feedEntries(surface, principal, { limit });
  const out = ['<?xml version="1.0" encoding="utf-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    '  <channel>',
    `    <title>${xml(man.vault.title ?? man.vault.id)}</title>`,
    `    <link>${xml(base + '/api/v1/tree')}</link>`,
    `    <description>Basalt vault ${xml(man.vault.id)}</description>`,
    `    <lastBuildDate>${rfc822(entries[0]?.mtime ?? now)}</lastBuildDate>`,
    `    <atom:link rel="self" type="application/rss+xml" href="${xml(base + '/feed.xml')}"/>`,
  ];
  for (const e of entries) {
    out.push('    <item>',
      `      <title>${xml(e.title)}</title>`,
      `      <link>${xml(nodeUrl(base, e.path))}</link>`,
      `      <guid isPermaLink="false">urn:basalt:node:${xml(e.id)}</guid>`,
      `      <pubDate>${rfc822(e.mtime)}</pubDate>`);
    for (const t of e.tags ?? []) out.push(`      <category>${xml(t)}</category>`);
    if (e.summary) out.push(`      <description>${xml(e.summary)}</description>`);
    out.push('    </item>');
  }
  out.push('  </channel>', '</rss>', '');
  return out.join('\n');
}

/**
 * A sitemap of what this principal may read.
 *
 * For `anonymous` on a public vault that is the crawlable set, which is what
 * a sitemap is for; for anyone else it is simply their own index, and the
 * `private, no-store` on the response keeps it theirs.
 */
export async function sitemap(surface, principal, { base }) {
  const rows = await surface.recent(principal, { limit: 500, publishedOnly: true });
  const out = ['<?xml version="1.0" encoding="utf-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'];
  for (const e of rows) {
    out.push('  <url>', `    <loc>${xml(nodeUrl(base, e.path))}</loc>`);
    const d = iso(e.mtime, null);
    if (d) out.push(`    <lastmod>${d.slice(0, 10)}</lastmod>`);
    out.push('  </url>');
  }
  out.push('</urlset>', '');
  return out.join('\n');
}

export function opensearch(surface, { base }) {
  const man = surface.manifest();
  const title = man.vault.title ?? man.vault.id;
  return ['<?xml version="1.0" encoding="utf-8"?>',
    '<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">',
    `  <ShortName>${xml(title.slice(0, 16))}</ShortName>`,
    `  <Description>Search the Basalt vault ${xml(title)}</Description>`,
    '  <InputEncoding>UTF-8</InputEncoding>',
    `  <Url type="application/json" method="GET" template="${xml(base + '/api/v1/search?q={searchTerms}')}"/>`,
    '</OpenSearchDescription>', ''].join('\n');
}

/**
 * robots.txt follows the audience ceiling (§12.2), not the ACL: a gated or
 * private vault asks crawlers to stay out entirely, because every path a
 * crawler could record is one an authenticated reader would have had to be
 * granted.
 */
export function robots(surface, { base }) {
  const audience = surface.manifest().publish.audience;
  if (audience !== 'public') {
    return `User-agent: *\nDisallow: /\n\n# audience=${audience} (PROTOCOL §12.2)\n`;
  }
  return 'User-agent: *\nAllow: /\nDisallow: /dav/\n'
    + `Sitemap: ${base}/sitemap.xml\n`;
}
