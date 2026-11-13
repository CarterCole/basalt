// Static site export, PROTOCOL §12.6.
//
// The rule that governs this file: a static host has no gatekeeper, so every
// byte written here is readable by anyone who finds the URL. The ACL model
// therefore degrades to a build-time filter — a node is exported only if it
// grants BOTH `read` and `publish` to `anonymous` (§8.1) — and the indexes
// are REGENERATED from that filtered subset rather than copied, because the
// vault's own indexes know about every private node (§8.8).
//
// Getting that backwards is the single worst mistake available in this
// codebase: copying index/ to a public bucket publishes the private half of
// the link graph while every page looks correct.

import { mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Vault } from '../vault.mjs';
import { Site } from './site.mjs';
import { canonicalJson } from '../canonical.mjs';
import { buildIndexes, buildSearchIndex } from '../indexer.mjs';
import { sortUtf8 } from '../keys.mjs';
import { ICON_SVG } from './pages.mjs';
import { vendorFile, hasDiagrams, MERMAID_JS } from './vendor.mjs';

const PUBLIC = fileURLToPath(new URL('./public/', import.meta.url));
const ANON = 'anonymous';

/**
 * Prefix every site-absolute URL with `base`, for a project page served from
 * https://user.github.io/repo/ rather than a domain root.
 *
 * Done as a pass over the emitted HTML rather than threaded through every
 * href-producing function, so there is exactly one place where a base path
 * can be got wrong, and it is testable on its own.
 */
export function applyBase(html, base) {
  if (!base || base === '/') return html;
  const prefix = '/' + base.replace(/^\/+|\/+$/g, '');
  // `data` is <object data>, which a PDF embed uses. The lookbehind keeps an
  // attribute that only ends in one of these names, like `data-src`, out.
  return html.replace(
    /(?<![\w-])(href|src|data)="\/(?!\/)([^"]*)"/g,
    (_, attr, rest) => `${attr}="${prefix}/${rest}"`,
  );
}

// File types a browser opens as a document, running any script inside, when
// a static host serves them by their extension. A gatekeeper answers for these
// with headers that make them inert (serve/core.mjs authorBytesHeaders); a
// static host sends no such headers, so the export leaves them out.
const DOCUMENT_EXT = new Set([
  '.html', '.htm', '.xhtml', '.xht', '.shtml', '.mht', '.mhtml',
  '.xml', '.xsl', '.xslt', '.svgz',
]);

const SVG_NS = 'http://www.w3.org/2000/svg';
const SVG_ELEMENTS = new Set([
  'svg', 'g', 'defs', 'symbol', 'use', 'switch', 'title', 'desc', 'style',
  'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon',
  'text', 'tspan', 'textpath', 'image',
  'lineargradient', 'radialgradient', 'stop', 'clippath', 'mask', 'pattern', 'marker',
  'filter', 'feblend', 'fecolormatrix', 'fecomponenttransfer', 'fecomposite',
  'feconvolvematrix', 'fediffuselighting', 'fedisplacementmap', 'fedistantlight',
  'fedropshadow', 'feflood', 'fefunca', 'fefuncb', 'fefuncg', 'fefuncr',
  'fegaussianblur', 'femerge', 'femergenode', 'femorphology', 'feoffset',
  'fepointlight', 'fespecularlighting', 'fespotlight', 'fetile', 'feturbulence',
]);

function decodeXmlText(s) {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|amp|lt|gt|quot|apos);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k[0] === '#') {
      const cp = k[1] === 'x' ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[k];
  });
}

/**
 * True when an SVG is only a drawing: nothing in it can run script, load
 * another document or link anywhere, even opened on its own.
 *
 * This is an allowlist, and it refuses whatever it does not recognise rather
 * than trying to name what is dangerous: plain SVG elements only, no element
 * from another namespace (which is how XHTML's <script> gets into an SVG), no
 * event attribute, no `href` that leaves the file, no DTD (entities can carry
 * markup), no processing instruction, no CDATA. Drawings saved by an editor
 * with its own metadata elements fail it; re-save those as plain SVG.
 */
export function isInertSvg(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  text = text.replace(/^\uFEFF/, '').replace(/^\s*<\?xml\s[^?]*\?>/, '');
  if (/<!DOCTYPE|<!ENTITY|<!\[CDATA\[|<\?/i.test(text)) return false;
  text = text.replace(/<!--[\s\S]*?-->/g, '');
  let ok = true;
  let sawRoot = false;
  const rest = text.replace(
    /<(\/?)([^\s<>\/"'=]*)((?:[^<>"']|"[^"]*"|'[^']*')*)>/g,
    (_, closing, name, attrs) => {
      const el = name.toLowerCase();
      if (!/^[a-z][a-z0-9]*$/.test(el) || !SVG_ELEMENTS.has(el)) ok = false;
      if (!sawRoot) { sawRoot = true; if (el !== 'svg' || closing) ok = false; }
      if (closing) { if (attrs.trim()) ok = false; return ''; }
      const leftover = attrs.replace(
        /\s+([^\s=<>"'\/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g,
        (__, rawName, dq, sq) => {
          const attr = rawName.toLowerCase();
          const local = attr.slice(attr.lastIndexOf(':') + 1);
          const value = decodeXmlText(dq ?? sq ?? '').trim();
          if (!attr.includes(':') && attr.startsWith('on')) ok = false;
          if (attr === 'xmlns' && value !== SVG_NS) ok = false;
          if (local === 'href' && !value.startsWith('#')
              && !(el === 'image' && /^data:image\/(png|jpe?g|gif|webp);base64,[a-z0-9+\/=\s]*$/i.test(value))) {
            ok = false;
          }
          return '';
        });
      if (leftover.replace(/\/$/, '').trim()) ok = false;
      return '';
    });
  return ok && sawRoot && !rest.includes('<') && !rest.includes('>');
}

/**
 * Why a published non-note cannot go on a static host as a file, or null.
 */
export function unsafeOnStaticHost(vaultPath, bytes) {
  const ext = (vaultPath.match(/\.[^./]+$/) ?? [''])[0].toLowerCase();
  if (DOCUMENT_EXT.has(ext)) return 'a browser would open it as a page and run its script';
  if (ext === '.svg' && !isInertSvg(bytes)) {
    return 'this SVG holds more than a drawing (script, links, foreign markup, or an '
      + "editor's own metadata)";
  }
  return null;
}

/** Where a vault path lands in the output tree. */
function outputPathFor(vaultPath, kind) {
  if (kind === 'note') {
    // Directory + index.html, so /Geology/Basalt works on any static host
    // without relying on a server's extension-stripping behaviour.
    const clean = vaultPath.replace(/\.(md|markdown)$/i, '');
    return `${clean}/index.html`;
  }
  return vaultPath;
}

/**
 * Export the public subset of a vault as a static site.
 *
 * @param {object} opts
 * @param {Vault} opts.vault
 * @param {string} opts.out        output directory
 * @param {string} [opts.base]     base path for a project page, e.g. "/repo"
 * @param {boolean} [opts.withVault] also emit a re-servable filtered vault
 * @param {boolean} [opts.clean]   remove the output directory first
 */
export async function exportSite({ vault, out, base = '', withVault = false, clean = false, log = () => {} }) {
  const outDir = path.resolve(out);
  if (clean) await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  const site = new Site(vault);
  const entries = vault.indexes?.nodes?.entries ?? [];

  // ---- the filter (§12.6) -------------------------------------------------
  const isPublic = (p) => vault.can(ANON, p, ['read']).allowed;
  const published = entries.filter((e) => isPublic(e.path));
  const withheld = entries.filter((e) => !isPublic(e.path));

  log(`${published.length} public, ${withheld.length} withheld`);
  for (const w of withheld) log(`  withheld: ${w.path}`, 'dim');

  if (!published.length) {
    throw Object.assign(
      new Error(
        `nothing to export: no node grants both read and publish to ` +
        `"${ANON}". A vault with audience "${vault.manifest.publish?.audience}" ` +
        `and no publish grants exports an empty site, which is almost never ` +
        `what someone wants — check §8.1 and §12.2.`),
      { code: 'NOTHING_PUBLIC' });
  }

  const write = async (rel, body) => {
    const file = path.join(outDir, rel);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, body);
  };

  // ---- pages --------------------------------------------------------------
  let pages = 0;
  // Mermaid's 5 MB bundle is copied only when some page has a diagram.
  let diagrams = false;
  const note = (html) => { diagrams ||= hasDiagrams(html); };
  for (const entry of published) {
    // Read once, as the anonymous reader: these are the bytes that would be
    // published, and a file a browser would run is not published as a file.
    const raw = await vault.readNode(ANON, entry.path);
    if (entry.kind !== 'note' && raw.status === 200) {
      const why = unsafeOnStaticHost(entry.path, raw.bytes);
      if (why) {
        log(`  not exported: ${entry.path} (${why})`, 'warn');
        continue;
      }
    }
    const res = await site.handle({
      urlPath: '/' + entry.path.replace(/\.(md|markdown)$/i, ''),
      query: new URLSearchParams(),
      principal: ANON,
    });
    if (res.status !== 200) {
      log(`  skipped ${entry.path} (status ${res.status})`, 'warn');
      continue;
    }
    if (entry.kind === 'note') note(String(res.body));
    const body = entry.kind === 'note'
      ? applyBase(markStatic(String(res.body)), base)
      : res.body;
    await write(outputPathFor(entry.path, entry.kind), body);

    // Raw bytes, which the HTML references for images and "View source".
    if (raw.status === 200) await write(path.join('_raw', entry.path), raw.bytes);
    pages++;
  }

  // ---- home ---------------------------------------------------------------
  const home = await site.handle({
    urlPath: '/', query: new URLSearchParams(), principal: ANON,
  });
  await write('index.html', applyBase(markStatic(String(home.body)), base));

  // ---- 404 ----------------------------------------------------------------
  const missing = await site.handle({
    urlPath: '/__basalt_not_found__', query: new URLSearchParams(), principal: ANON,
  });
  await write('404.html', applyBase(markStatic(String(missing.body)), base));

  // ---- assets -------------------------------------------------------------
  for (const name of ['site.css', 'site.js']) {
    await write(path.join('_assets', name), await readFile(path.join(PUBLIC, name)));
  }
  await write(path.join('_assets', 'icon.svg'), ICON_SVG);
  note(String(home.body));
  if (diagrams) {
    await write(path.join('_assets', MERMAID_JS), await readFile(vendorFile(MERMAID_JS)));
  }

  // ---- search, client-side -------------------------------------------------
  // There is no server to query, so the postings ship to the browser. They
  // are built from the PUBLIC subset only: this file is world-readable, so
  // anything in it is published, by definition.
  const publicPaths = new Set(published.map((e) => e.path));
  const searchIndex = {
    basalt: 1,
    kind: 'static-search',
    nodes: published
      .filter((e) => e.kind === 'note' || e.kind === 'data')
      .map((e) => ({
        id: e.id,
        title: e.title ?? e.path,
        path: e.path,
        href: joinBase(base, '/' + e.path.replace(/\.(md|markdown)$/i, '')),
      })),
    terms: filterTerms(vault.indexes?.search?.terms ?? {}, published),
  };
  await write(path.join('_assets', 'search-index.json'), canonicalJson(searchIndex));

  // ---- Pages housekeeping --------------------------------------------------
  // Without this, GitHub Pages runs Jekyll, which ignores every directory
  // whose name starts with an underscore — including _assets/ and _raw/.
  await write('.nojekyll', '');

  // ---- the filtered vault (§12.6: an export is itself a vault) -------------
  if (withVault) {
    const publicScan = [];
    for (const e of published) {
      const r = await vault.readNode(ANON, e.path);
      if (r.status === 200) {
        publicScan.push({
          key: 'content/' + e.path, path: e.path,
          bytes: Buffer.from(r.bytes), stat: { size: r.bytes.length, etag: null },
        });
      }
    }
    const rebuilt = buildIndexes({
      scanned: publicScan,
      vaultId: vault.manifest.vault.id,
      sidecars: vault.sidecars,
      folderRecords: vault.folderRecords,
    });
    const search = buildSearchIndex({
      nodes: rebuilt._nodes, vaultId: vault.manifest.vault.id,
      sourceDigest: rebuilt.digest.root, isPublic: () => true,
    });

    for (const item of publicScan) {
      await write(path.join('vault', item.key), item.bytes);
    }
    for (const [name, obj] of Object.entries({ ...rebuilt, search })) {
      if (name.startsWith('_')) continue;
      await write(path.join('vault', 'index', `${name}.json`), canonicalJson(obj));
    }
    const manifest = {
      ...vault.manifest,
      publish: { ...vault.manifest.publish, audience: 'public' },
    };
    await write(path.join('vault', 'basalt.yaml'),
      `# Exported public subset of ${vault.manifest.vault.id}.\n` +
      `# Regenerated per §12.6 — these indexes describe only public nodes.\n` +
      yamlish(manifest));
    log(`wrote a re-servable filtered vault under vault/`);
  }

  return {
    outDir,
    pages,
    published: published.length,
    withheld: withheld.map((e) => e.path),
    digest: vault.indexes?.digest?.root ?? null,
  };
}

/** Keep only postings whose node is in the published set. */
function filterTerms(terms, published) {
  const ids = new Set(published.map((e) => e.id).filter(Boolean));
  const out = {};
  for (const [term, postings] of Object.entries(terms)) {
    const kept = postings.filter((p) => ids.has(p.node));
    if (kept.length) out[term] = kept;
  }
  return out;
}

function joinBase(base, p) {
  if (!base || base === '/') return p;
  return '/' + base.replace(/^\/+|\/+$/g, '') + p;
}

/** Tell site.js there is no server behind this page. */
function markStatic(html) {
  return html.replace('</head>', '<meta name="basalt-static" content="1">\n</head>');
}

/** A small YAML writer for the exported manifest — no dependency needed. */
function yamlish(obj, indent = 0) {
  const pad = '  '.repeat(indent);
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    if (Array.isArray(v)) {
      out += `${pad}${k}: [${v.map((x) => JSON.stringify(x)).join(', ')}]\n`;
    } else if (typeof v === 'object') {
      out += `${pad}${k}:\n${yamlish(v, indent + 1)}`;
    } else {
      const needsQuote = typeof v === 'string' && /[:#\n]|^\s|\s$/.test(v);
      out += `${pad}${k}: ${needsQuote ? JSON.stringify(v) : v}\n`;
    }
  }
  return out;
}
