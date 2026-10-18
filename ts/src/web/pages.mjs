// Server-rendered pages for the publish site.
//
// Everything a reader needs is in the HTML: content, nav, backlinks, graph
// and table of contents. site.js only adds search-as-you-type, a theme
// toggle and scroll-spy, so the site is fully readable with script disabled —
// which also means a crawler and a text browser see the real page.
//
// Every string that came from vault content goes through escapeHtml, except
// `prose`, which is the renderer's own output and already escaped there.

import { escapeHtml, hrefFor } from './markdown.mjs';
import { parentFolder, basename, stem } from '../keys.mjs';

const MARK = `<svg class="brand-mark" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
<path fill="currentColor" d="M12 2 20.5 7v10L12 22 3.5 17V7z" opacity=".22"/>
<path fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" d="M12 2 20.5 7v10L12 22 3.5 17V7z"/>
<path fill="none" stroke="currentColor" stroke-width="1.2" d="M12 2v20M3.5 7l17 10M20.5 7l-17 10"/>
</svg>`;

const CARET = `<svg class="nav-caret" width="11" height="11" viewBox="0 0 16 16" aria-hidden="true">
<path fill="currentColor" d="M6 3.5 11 8l-5 4.5z"/></svg>`;

const SUN_MOON = `<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
<path fill="currentColor" d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"/></svg>`;

const BURGER = `<svg width="17" height="17" viewBox="0 0 24 24" aria-hidden="true">
<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M4 7h16M4 12h16M4 17h16"/></svg>`;

/** The document shell. */
export function shell({ vault, nav, body, title, description, canonicalPath, indexState }) {
  const vaultTitle = vault.title ?? 'Vault';
  const pageTitle = title ? `${title} · ${vaultTitle}` : vaultTitle;
  return `<!doctype html>
<html lang="${escapeHtml(vault.locale ?? 'en')}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(pageTitle)}</title>
${description ? `<meta name="description" content="${escapeHtml(description)}">` : ''}
<meta property="og:title" content="${escapeHtml(title ?? vaultTitle)}">
${description ? `<meta property="og:description" content="${escapeHtml(description)}">` : ''}
<meta property="og:type" content="article">
<link rel="stylesheet" href="/_assets/site.css">
<link rel="icon" href="/_assets/icon.svg" type="image/svg+xml">
</head>
<body>
<div class="topbar">
  <button class="icon-btn" data-nav-toggle aria-label="Open navigation">${BURGER}</button>
  <a class="brand-name" href="/">${MARK}${escapeHtml(vaultTitle)}</a>
</div>
<div class="shell">
  <aside class="sidebar" data-sidebar>
    <div class="brand">
      <a class="brand-name" href="/">${MARK}${escapeHtml(vaultTitle)}</a>
      <div class="brand-sub">Basalt vault</div>
    </div>
    <form class="search" action="/_search" method="get" role="search">
      <input class="search-input" type="search" name="q" data-search
             placeholder="Search notes…  /" autocomplete="off"
             aria-label="Search notes">
      <div class="search-results" data-search-results></div>
    </form>
    <nav class="nav" aria-label="Vault contents">${nav}</nav>
  </aside>
  <main class="main"><div class="main-inner">${body}</div></main>
</div>
<button class="icon-btn theme-toggle" data-theme-toggle aria-label="Switch theme">${SUN_MOON}</button>
<script src="/_assets/site.js" defer></script>
</body>
</html>`;
}

/**
 * The nav tree, recursive. Uses <details> so folders collapse without JS,
 * and opens the ancestors of the current page.
 */
export function navTree(node, currentPath, depth = 0) {
  if (!node) return '';
  const items = node.entries.map((e) => {
    const current = e.path === currentPath;
    return `<a class="nav-item" href="${hrefFor(e.path)}"` +
      `${current ? ' aria-current="page"' : ''}>${escapeHtml(e.title ?? basename(e.path))}</a>`;
  }).join('');

  const folders = node.folders.map((f) => {
    const open = currentPath?.startsWith(f.folder) ?? false;
    const label = escapeHtml(f.title ?? basename(f.folder.replace(/\/$/, '')));
    return `<details class="nav-group"${open ? ' open' : ''}>` +
      `<summary>${CARET}${label}</summary>` +
      `<div class="nav-children">${navTree(f, currentPath, depth + 1)}</div>` +
      `</details>`;
  }).join('');

  return folders + items;
}

function breadcrumbs(path, vaultTitle) {
  const parts = path.split('/');
  parts.pop();
  const crumbs = [`<a href="/">${escapeHtml(vaultTitle)}</a>`];
  let acc = '';
  for (const p of parts) {
    acc += p + '/';
    crumbs.push(`<span>/</span><span>${escapeHtml(p)}</span>`);
  }
  return `<nav class="crumbs" aria-label="Breadcrumb">${crumbs.join('')}</nav>`;
}

/**
 * A local graph: the node plus its immediate neighbours on a circle.
 *
 * Rendered as SVG server-side with positions computed here — no layout
 * library, no script, and it prints. Redacted neighbours appear as dashed
 * locked nodes rather than being dropped, for the same reason §9.5 keeps
 * redacted edges: a graph with holes silently misinforms.
 */
export function localGraph({ center, neighbours }) {
  const shown = neighbours.slice(0, 12);
  if (!shown.length) return '';

  // Size the canvas to the node count: a three-neighbour graph in a box built
  // for twelve is mostly empty space.
  const R = Math.min(122, 74 + shown.length * 5);
  const W = 560;
  const H = Math.round(2 * R + 92);
  const cx = W / 2, cy = H / 2;

  const pts = shown.map((n, i) => {
    const a = (i / shown.length) * Math.PI * 2 - Math.PI / 2;
    return { ...n, x: cx + Math.cos(a) * R, y: cy + Math.sin(a) * R, a };
  });

  const edges = pts.map((p) =>
    `<line class="graph-edge${p.locked ? ' redacted' : ''}" ` +
    `x1="${cx}" y1="${cy}" x2="${p.x.toFixed(1)}" y2="${p.y.toFixed(1)}"/>`,
  ).join('');

  const nodes = pts.map((p) => {
    // Push the label outward so it never sits on top of its own edge.
    const lx = cx + Math.cos(p.a) * (R + 16);
    const ly = cy + Math.sin(p.a) * (R + 16);
    const anchor = Math.abs(Math.cos(p.a)) < 0.3
      ? 'middle' : (Math.cos(p.a) > 0 ? 'start' : 'end');
    const label = escapeHtml(truncate(p.title ?? 'Restricted', 22));
    const circle = `<circle class="graph-node${p.locked ? ' locked' : ''}" ` +
      `cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="6"/>`;
    const text = `<text class="graph-label" x="${lx.toFixed(1)}" y="${(ly + 3.5).toFixed(1)}" ` +
      `text-anchor="${anchor}">${label}</text>`;
    return p.locked
      ? `<g>${circle}${text}<title>Restricted</title></g>`
      : `<a class="graph-hit" href="${hrefFor(p.path)}"><g>${circle}${text}` +
        `<title>${escapeHtml(p.title ?? p.path)}</title></g></a>`;
  }).join('');

  return `<section class="panel">
<h2 class="panel-head">Local graph <span class="panel-count">${shown.length}</span></h2>
<svg class="graph" viewBox="0 0 ${W} ${H}" role="img"
     aria-label="Notes linked to this one">
${edges}
<circle class="graph-node center" cx="${cx}" cy="${cy}" r="8"/>
<text class="graph-label" x="${cx}" y="${cy + 24}" text-anchor="middle">${escapeHtml(truncate(center.title ?? '', 26))}</text>
${nodes}
</svg>
</section>`;
}

function truncate(s, n) {
  const t = String(s);
  return t.length <= n ? t : t.slice(0, n - 1) + '…';
}

/** The backlinks panel (§10.3), with redacted sources kept visible. */
function backlinksPanel(backlinks) {
  const body = backlinks.length
    ? backlinks.map((b) => b.id === 'redacted'
      ? `<div class="backlink"><span class="backlink-locked">${
          b.title ? escapeHtml(b.title) : 'A note you cannot access'}</span></div>`
      : `<div class="backlink"><a class="backlink-title" href="${hrefFor(b.path)}">${
          escapeHtml(b.title ?? b.path)}</a>` +
        `<span class="backlink-path">${escapeHtml(b.path)}</span></div>`).join('')
    : `<p class="panel-empty">Nothing links here yet.</p>`;
  return `<section class="panel">
<h2 class="panel-head">Linked from <span class="panel-count">${backlinks.length}</span></h2>
${body}
</section>`;
}

/** A note page. */
export function notePage({
  vault, node, prose, toc, backlinks, graph, tags, stale,
}) {
  const tocHtml = toc.length
    ? `<aside class="toc"><div class="toc-head">On this page</div>${
        toc.map((h) => `<a class="lvl-${h.level}" href="#${encodeURIComponent(h.id)}">${
          escapeHtml(h.text)}</a>`).join('')}</aside>`
    : '<aside class="toc"></aside>';

  const tagsHtml = tags.length
    ? tags.map((t) => `<a class="tag" href="/_search?q=${encodeURIComponent('#' + t)}">#${
        escapeHtml(t)}</a>`).join('')
    : '';

  return `<article class="article">
${breadcrumbs(node.path, vault.title ?? 'Vault')}
<h1 class="title">${escapeHtml(node.title ?? stem(basename(node.path)))}</h1>
<div class="meta">
  <span>${escapeHtml(node.path)}</span>
  ${tagsHtml}
</div>
${stale ? `<p class="notice">This page was built from an index that is out of
 date with the vault's content. What you see may be missing recent changes.</p>` : ''}
<div class="prose">${prose}</div>
<div class="panels">
${backlinksPanel(backlinks)}
${graph}
</div>
<footer class="footer">
  <span>Served by Basalt · <code>${escapeHtml(vault.id)}</code></span>
  <a href="/_raw/${node.path.split('/').map(encodeURIComponent).join('/')}">View source</a>
</footer>
</article>
${tocHtml}`;
}

/** The vault home: the entry note, or a listing when none is set. */
export function homePage({ vault, tree }) {
  const count = countEntries(tree);
  return `<article class="article">
<h1 class="title">${escapeHtml(vault.title ?? 'Vault')}</h1>
<div class="meta"><span>${count} note${count === 1 ? '' : 's'} you can read</span></div>
<div class="prose">
<p>This vault has no entry note configured. Pick something from the sidebar,
or set <code>publish.home</code> in <code>basalt.yaml</code> to choose what
readers land on.</p>
</div>
<footer class="footer"><span>Served by Basalt · <code>${escapeHtml(vault.id)}</code></span></footer>
</article>
<aside class="toc"></aside>`;
}

function countEntries(node) {
  if (!node) return 0;
  return node.entries.length + node.folders.reduce((n, f) => n + countEntries(f), 0);
}

/** Server-rendered search results — the no-JS path, and a shareable URL. */
export function searchPage({ vault, query, hits }) {
  const body = !query
    ? `<p class="panel-empty">Type a query to search this vault.</p>`
    : hits.length
      ? hits.map((h) => `<div class="backlink">` +
          `<a class="backlink-title" href="${hrefFor(h.path)}">${escapeHtml(h.title ?? h.path)}</a>` +
          `<span class="backlink-path">${escapeHtml(h.path)}</span></div>`).join('')
      : `<p class="panel-empty">No notes match “${escapeHtml(query)}”.</p>`;

  return `<article class="article">
<h1 class="title">Search</h1>
<div class="meta"><span>${query ? `${hits.length} result${hits.length === 1 ? '' : 's'} for “${escapeHtml(query)}”` : 'All readable notes'}</span></div>
<div class="panels"><section class="panel">${body}</section></div>
</article>
<aside class="toc"></aside>`;
}

/**
 * An error page.
 *
 * §12.3 requires 404 and 403 to be told apart by discoverability, and the
 * copy must not undo that: a 404 says nothing about whether the path exists,
 * because saying "this exists but you may not see it" to someone who was not
 * allowed to discover it is the leak the status split exists to prevent.
 */
export function errorPage({ vault, status }) {
  const copy = {
    404: {
      title: 'Not found',
      body: 'There is nothing to show at this address.',
    },
    403: {
      title: 'You do not have access',
      body: 'This note exists, but your account cannot read it. Ask whoever ' +
        'maintains this vault if you think that is wrong.',
    },
    401: {
      title: 'Sign in required',
      body: 'This vault is not public. You need an account to read it.',
    },
    500: {
      title: 'Something broke',
      body: 'The server could not render this page.',
    },
  }[status] ?? { title: 'Error', body: 'Something went wrong.' };

  return `<article class="article"><div class="error-page">
<div class="error-code">${status}</div>
<h1 class="error-title">${escapeHtml(copy.title)}</h1>
<p class="error-body">${escapeHtml(copy.body)}</p>
<p class="error-body"><a href="/">Back to ${escapeHtml(vault.title ?? 'the vault')}</a></p>
</div></article>
<aside class="toc"></aside>`;
}

export const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
<rect width="24" height="24" rx="4" fill="#1c1a19"/>
<path fill="none" stroke="#b4530f" stroke-width="1.7" stroke-linejoin="round" d="M12 4 18.9 8v8L12 20 5.1 16V8z"/>
<path fill="none" stroke="#b4530f" stroke-width="1.1" opacity=".75" d="M12 4v16M5.1 8l13.8 8M18.9 8 5.1 16"/>
</svg>`;
