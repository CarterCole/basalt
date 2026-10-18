// The publish site router, PROTOCOL §12.
//
// Pages are rendered per principal: the nav tree, the prose, the backlinks
// and the graph are all built from what this reader may see. Nothing is
// cached across principals here — the Gatekeeper's own cache is keyed by
// subject set (§12.5) and this layer holds no cache of its own, which is the
// simplest way not to leak one reader's visibility to another.

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildResolver } from '../links.mjs';
import { pathToKey, parentFolder, basename, extname } from '../keys.mjs';
import { createRenderer, hrefFor, pathCandidates, escapeHtml } from './markdown.mjs';
import {
  shell, navTree, notePage, homePage, searchPage, errorPage, localGraph, ICON_SVG,
} from './pages.mjs';

const PUBLIC = fileURLToPath(new URL('./public/', import.meta.url));

const MEDIA = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif',
  '.pdf': 'application/pdf',
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json', '.yaml': 'text/yaml', '.yml': 'text/yaml',
  '.txt': 'text/plain; charset=utf-8',
};
const mediaFor = (p) => MEDIA[extname(p)] ?? 'application/octet-stream';

export class Site {
  constructor(vault) {
    this.vault = vault;
    this.assets = new Map();
  }

  #manifestView() {
    const m = this.vault.manifest;
    return {
      id: m.vault.id,
      title: m.vault.title,
      locale: m.vault.default_locale ?? 'en',
    };
  }

  /** Per-request rendering context bound to one principal. */
  #context(principal) {
    const entries = this.vault.indexes?.nodes?.entries ?? [];
    const byPath = new Map(entries.map((e) => [e.path, e]));
    const byId = new Map(entries.filter((e) => e.id).map((e) => [e.id, e]));

    // The resolver spans EVERY node, not just the visible ones, so a link
    // resolves to the same node the index resolved it to (§9.2). Visibility
    // is applied afterwards, as redaction (§9.5) — not by hiding the target
    // from the resolver, which would silently turn a restricted link into a
    // dangling one.
    const resolver = buildResolver(entries
      .filter((e) => e.id)
      .map((e) => ({ id: e.id, path: e.path, aliases: e.aliases ?? [] })));

    const readable = new Map();
    const canRead = (p) => {
      if (!readable.has(p)) {
        readable.set(p, this.vault.can(principal, p, ['read']).allowed);
      }
      return readable.get(p);
    };

    return { entries, byPath, byId, resolver, canRead };
  }

  /** Resolve a URL path to a vault path the principal may read. */
  #lookup(urlPath, ctx) {
    for (const candidate of pathCandidates(urlPath)) {
      if (ctx.byPath.has(candidate)) return candidate;
    }
    return null;
  }

  /**
   * §12.3: 404 when the reader could not know the object exists, 403 when it
   * may. A 403 on a path the requester was not allowed to discover confirms
   * that path exists.
   */
  #denialStatus(principal, vaultPath) {
    const folder = parentFolder(vaultPath);
    return this.vault.can(principal, folder, ['list']).allowed ? 403 : 404;
  }

  async #asset(name) {
    if (name === 'icon.svg') return { body: ICON_SVG, type: 'image/svg+xml' };
    if (!/^[a-z0-9.\-]+$/i.test(name) || name.includes('..')) return null;
    if (!this.assets.has(name)) {
      try {
        this.assets.set(name, await readFile(path.join(PUBLIC, name)));
      } catch { return null; }
    }
    return { body: this.assets.get(name), type: mediaFor(name) };
  }

  /** Build the nav tree for this principal. */
  #nav(principal, currentPath) {
    const { tree } = this.vault.tree(principal);
    return navTree(tree, currentPath);
  }

  #page(bodyHtml, { title, description, principal, currentPath }) {
    return shell({
      vault: this.#manifestView(),
      nav: this.#nav(principal, currentPath),
      body: bodyHtml,
      title,
      description,
    });
  }

  /**
   * Handle a request. Returns {status, headers, body} or null when the path
   * is not the site's business (so the Gatekeeper can try its API routes).
   */
  async handle({ urlPath, query, principal }) {
    const html = (status, body) => ({
      status,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body,
    });
    const vaultView = this.#manifestView();
    const fail = (status, principalId, currentPath) => html(status, this.#page(
      errorPage({ vault: vaultView, status }),
      { title: String(status), principal: principalId, currentPath }));

    // ---- static assets
    if (urlPath.startsWith('/_assets/')) {
      const a = await this.#asset(urlPath.slice('/_assets/'.length));
      if (!a) return { status: 404, headers: {}, body: 'not found' };
      return {
        status: 200,
        headers: {
          'content-type': a.type,
          // Assets are versionless here; a short cache keeps a reload cheap
          // without stranding a reader on an old stylesheet.
          'cache-control': 'public, max-age=300',
        },
        body: a.body,
      };
    }

    const ctx = this.#context(principal);

    // ---- raw bytes (images, source view)
    if (urlPath.startsWith('/_raw/')) {
      const target = decodePath(urlPath.slice('/_raw/'.length));
      if (target === null) return fail(404, principal, null);
      const r = await this.vault.readNode(principal, target);
      if (r.status !== 200) return fail(r.status, principal, null);
      return {
        status: 200,
        headers: {
          'content-type': mediaFor(target),
          'cache-control': 'private, no-store',
          // Content is author-supplied; never let a browser sniff it into
          // something executable.
          'x-content-type-options': 'nosniff',
        },
        body: r.bytes,
      };
    }

    // ---- search
    if (urlPath === '/_search' || urlPath === '/_search.json') {
      const q = (query.get('q') ?? '').trim();
      const hits = q ? this.vault.search(principal, q).hits : [];
      if (urlPath === '/_search.json') {
        return {
          status: 200,
          headers: { 'content-type': 'application/json', 'cache-control': 'private, no-store' },
          body: JSON.stringify({
            query: q,
            hits: hits.slice(0, 20).map((h) => ({
              title: h.title ?? h.path, path: h.path, href: hrefFor(h.path),
            })),
          }),
        };
      }
      return html(200, this.#page(
        searchPage({ vault: vaultView, query: q, hits }),
        { title: q ? `Search: ${q}` : 'Search', principal, currentPath: null }));
    }

    // ---- home
    if (urlPath === '/' || urlPath === '') {
      const home = this.vault.manifest.publish?.home;
      if (home && ctx.byPath.has(home) && ctx.canRead(home)) {
        return this.#notePage(home, principal, ctx);
      }
      const { tree } = this.vault.tree(principal);
      return html(200, this.#page(
        homePage({ vault: vaultView, tree }),
        { title: null, principal, currentPath: null }));
    }

    // ---- a note
    const vaultPath = this.#lookup(urlPath, ctx);
    if (!vaultPath) return fail(404, principal, null);
    if (!ctx.canRead(vaultPath)) {
      return fail(this.#denialStatus(principal, vaultPath), principal, null);
    }

    // An asset addressed directly serves its bytes rather than a note page.
    const entry = ctx.byPath.get(vaultPath);
    if (entry.kind === 'asset' || entry.kind === 'opaque') {
      const r = await this.vault.readNode(principal, vaultPath);
      if (r.status !== 200) return fail(r.status, principal, null);
      return {
        status: 200,
        headers: {
          'content-type': mediaFor(vaultPath),
          'cache-control': 'private, no-store',
          'x-content-type-options': 'nosniff',
        },
        body: r.bytes,
      };
    }

    return this.#notePage(vaultPath, principal, ctx);
  }

  async #notePage(vaultPath, principal, ctx) {
    const r = await this.vault.readNode(principal, vaultPath);
    if (r.status !== 200) {
      return {
        status: r.status,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        body: this.#page(
          errorPage({ vault: this.#manifestView(), status: r.status }),
          { title: String(r.status), principal, currentPath: null }),
      };
    }

    const entry = ctx.byPath.get(vaultPath);
    const bodyCache = new Map();
    const renderer = createRenderer({
      resolver: ctx.resolver,
      byPath: ctx.byPath,
      canRead: ctx.canRead,
      redactTitles: this.vault.manifest.security?.redact_titles !== false,
      embedText: (p) => {
        if (!ctx.canRead(p)) return null;
        const e = ctx.byPath.get(p);
        if (!e || e.kind !== 'note') return null;
        return bodyCache.get(p) ?? null;
      },
    });

    // Transclusion needs the embedded notes' text, so fetch the bodies the
    // page actually embeds — one level, matching renderEmbed's depth limit.
    //
    // This map is request-local on purpose. Held on the instance it would be
    // shared between concurrent requests, and because these bodies were
    // fetched for ONE principal, a second reader's page could render content
    // fetched under the first reader's permissions.
    const body = stripFrontmatter(r.text ?? '');
    for (const m of body.matchAll(/!\[\[([^\[\]]+)\]\]/g)) {
      const c = renderer.classify(m[1], vaultPath);
      if (c.kind === 'ok' && c.entry?.kind === 'note' && !bodyCache.has(c.path)) {
        const sub = await this.vault.readNode(principal, c.path);
        if (sub.status === 200) {
          bodyCache.set(c.path, stripFrontmatter(sub.text ?? ''));
        }
      }
    }

    // The page renders the note's title itself, so a leading H1 that repeats
    // it would show twice. Strip it only when it MATCHES the title: §5.2
    // lets the title fall back to the first H1, so an H1 that differs is
    // genuine content and must stay.
    const prose = renderer.render(dropRedundantH1(body, entry.title), vaultPath);

    const links = this.vault.links(principal, vaultPath);
    const backlinks = links.status === 200 ? links.backlinks : [];

    // Neighbours for the graph: out-edges and backlinks, deduplicated.
    const seen = new Set();
    const neighbours = [];
    for (const e of (links.status === 200 ? links.out : [])) {
      if (!e.target || e.target.id === undefined) continue;
      const locked = e.target.id === 'redacted';
      const key = locked ? `locked:${neighbours.length}` : e.target.path;
      if (seen.has(key)) continue;
      seen.add(key);
      neighbours.push({ path: e.target.path, title: e.target.title, locked });
    }
    for (const b of backlinks) {
      const locked = b.id === 'redacted';
      const key = locked ? `locked:b${neighbours.length}` : b.path;
      if (seen.has(key)) continue;
      seen.add(key);
      neighbours.push({ path: b.path, title: b.title, locked });
    }

    const state = this.vault.indexes?.nodes?.source_digest
      !== this.vault.indexes?.digest?.root;

    const bodyHtml = notePage({
      vault: this.#manifestView(),
      node: entry,
      prose,
      toc: (entry.headings ?? [])
        .filter((h) => h.level >= 2 && h.level <= 3)
        .map((h) => ({ ...h, id: h.slug })),
      backlinks,
      graph: localGraph({ center: entry, neighbours }),
      tags: entry.tags ?? [],
      stale: state,
    });

    return {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'private, no-store',
      },
      body: this.#page(bodyHtml, {
        title: entry.title,
        description: firstSentence(body),
        principal,
        currentPath: vaultPath,
      }),
    };
  }
}

/** Remove a leading H1 when it merely repeats the note's title. */
function dropRedundantH1(body, title) {
  if (!title) return body;
  const lines = body.split('\n');
  let i = 0;
  while (i < lines.length && lines[i].trim() === '') i++;
  const m = lines[i]?.match(/^#\s+(.+?)\s*#*\s*$/);
  if (!m) return body;
  if (m[1].trim().normalize('NFC') !== title.trim().normalize('NFC')) return body;
  return lines.slice(i + 1).join('\n');
}

/** Decode a URL path per segment, or null if it is malformed or escapes. */
function decodePath(raw) {
  const p = raw.replace(/^\/+|\/+$/g, '');
  if (!p) return null;
  try {
    const segs = p.split('/').map(decodeURIComponent);
    if (segs.some((s) => s === '' || s === '.' || s === '..')) return null;
    return segs.join('/');
  } catch { return null; }
}

/** Drop a frontmatter block before rendering, so it is not shown as prose. */
function stripFrontmatter(text) {
  if (!text.startsWith('---')) return text;
  const lines = text.split('\n');
  if (lines[0].trimEnd() !== '---') return text;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trimEnd() === '---') return lines.slice(i + 1).join('\n');
  }
  return text;
}

/** A plain-text description for meta tags. */
function firstSentence(body) {
  const text = body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/!?\[\[([^\[\]|#]*)[^\[\]]*\]\]/g, '$1')
    .replace(/[#*_>`]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) return null;
  const cut = text.slice(0, 180);
  const stop = cut.lastIndexOf('. ');
  return (stop > 60 ? cut.slice(0, stop + 1) : cut).trim();
}
