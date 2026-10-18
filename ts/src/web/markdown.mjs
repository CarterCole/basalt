// Markdown rendering for the publish site, PROTOCOL §9.
//
// The hard requirement: this MUST resolve links exactly as the indexer does,
// using the same resolver over the same node set (§9.2), and only then apply
// the viewer's visibility (§9.5). Resolving independently would let the page
// disagree with index/links.json about what a wikilink means.
//
// Raw HTML in content is escaped rather than passed through. A vault can have
// several editors, and `write` on a note is not consent to run script in
// every reader's browser.

import { Marked } from 'marked';
import { resolveTarget, slugify, anchorResolves } from '../links.mjs';
import { extname } from '../keys.mjs';

const IMAGE_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.svg', '.bmp', '.ico',
]);

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * URL for a node path within the site.
 *
 * A note's markdown extension is dropped, because a published URL is a thing
 * people paste to each other and `/Notes/Hexes` survives that better than
 * `/Notes/Hexes.md`. Everything else keeps its extension, so the mapping back
 * is unambiguous: the router tries the exact path first, then appends the
 * markdown extensions, mirroring §9.2 steps 1-3.
 */
export function hrefFor(path, anchor) {
  const clean = path.replace(/\.(md|markdown)$/i, '');
  const encoded = clean.split('/').map(encodeURIComponent).join('/');
  return `/${encoded}${anchor ? '#' + encodeURIComponent(slugify(anchor)) : ''}`;
}

/**
 * The inverse of hrefFor: a URL path to a candidate vault path list.
 *
 * Decoding is per segment. Decoding the whole path at once would let a
 * `%2F` in a filename introduce a path separator that was not there.
 */
export function pathCandidates(urlPath) {
  const raw = urlPath.replace(/^\/+|\/+$/g, '');
  if (!raw) return [];
  let p;
  try {
    p = raw.split('/').map(decodeURIComponent).join('/');
  } catch {
    return [];  // malformed percent-encoding addresses nothing
  }
  if (p.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) return [];
  return [p, `${p}.md`, `${p}.markdown`];
}

/**
 * Build a renderer bound to one viewer.
 *
 * @param {object} ctx
 * @param {object} ctx.resolver       from buildResolver over ALL nodes
 * @param {(path: string) => boolean} ctx.canRead
 * @param {Map<string, object>} ctx.byPath  path → index node entry
 * @param {boolean} ctx.redactTitles
 * @param {(path: string) => string|null} [ctx.embedText] for transclusion
 */
export function createRenderer(ctx) {
  const marked = new Marked({ gfm: true, breaks: false });

  // The marked extension closures are registered once, so the path of the
  // note being rendered lives in this holder. `classify` takes it explicitly
  // as well, so a caller can resolve a link before any render has run.
  const state = { fromPath: null };

  /** Resolve one wikilink and describe how to render it. */
  const classify = (raw, fromPath = state.fromPath) => {
    let target = raw.trim();
    let alias = null;
    let anchor = null;
    const pipe = target.indexOf('|');
    if (pipe !== -1) { alias = target.slice(pipe + 1).trim(); target = target.slice(0, pipe); }
    const hash = target.indexOf('#');
    if (hash !== -1) { anchor = target.slice(hash + 1).trim(); target = target.slice(0, hash); }
    target = target.trim();

    if (!target) return { kind: 'skip' };

    if (fromPath == null) {
      throw new TypeError('classify: fromPath is required before any render');
    }
    const r = resolveTarget(ctx.resolver, fromPath, target);
    if (!r.node) return { kind: 'dangling', target, alias, anchor };

    const entry = ctx.byPath.get(r.node.path);
    if (!ctx.canRead(r.node.path)) {
      // §9.5: redacted, never removed. A reader must be able to tell a
      // redacted link from a dangling one.
      return {
        kind: 'redacted', target, alias, anchor,
        title: ctx.redactTitles ? null : entry?.title ?? null,
      };
    }
    return {
      kind: 'ok', target, alias, anchor,
      path: r.node.path,
      title: entry?.title ?? r.node.path,
      entry,
      anchorOk: anchorResolves(anchor, entry?.headings, entry?.blockIds),
    };
  };

  marked.use({
    extensions: [{
      name: 'basaltLink',
      level: 'inline',
      start(src) {
        const embed = src.indexOf('![[');
        const plain = src.indexOf('[[');
        if (embed === -1) return plain === -1 ? undefined : plain;
        if (plain === -1) return embed;
        return Math.min(embed, plain);
      },
      tokenizer(src) {
        const m = /^(!?)\[\[([^\[\]]*)\]\]/.exec(src);
        if (!m) return undefined;
        return {
          type: 'basaltLink',
          raw: m[0],
          isEmbed: m[1] === '!',
          body: m[2],
        };
      },
      renderer(token) {
        const c = classify(token.body);
        if (c.kind === 'skip') return escapeHtml(token.raw);

        if (c.kind === 'dangling') {
          const label = c.alias ?? c.target;
          return `<span class="lk lk-dead" title="This note does not exist yet"` +
            ` data-target="${escapeHtml(c.target)}">${escapeHtml(label)}</span>`;
        }

        if (c.kind === 'redacted') {
          // The label must not leak a title the viewer may not see.
          const label = c.title ?? c.alias ?? 'Restricted';
          return `<span class="lk lk-locked" title="You do not have access to this note"` +
            ` aria-label="Restricted link">${escapeHtml(label)}</span>`;
        }

        if (token.isEmbed) return renderEmbed(c, ctx);

        const label = c.alias ?? (c.anchor && c.anchorOk
          ? `${c.title} § ${c.anchor}` : c.title);
        const cls = c.anchorOk ? 'lk lk-note' : 'lk lk-note lk-anchor-missing';
        return `<a class="${cls}" href="${hrefFor(c.path, c.anchor)}"` +
          `>${escapeHtml(label)}</a>`;
      },
    }],
    renderer: {
      // Escape author HTML instead of emitting it.
      html(token) { return escapeHtml(token.raw ?? token.text ?? ''); },
      heading({ tokens, depth }) {
        const text = this.parser.parseInline(tokens);
        const plain = stripTags(text);
        const id = slugify(plain);
        return `<h${depth} id="${escapeHtml(id)}">` +
          `<a class="anchor" href="#${escapeHtml(id)}" aria-hidden="true">#</a>` +
          `${text}</h${depth}>\n`;
      },
      link({ href, title, tokens }) {
        const text = this.parser.parseInline(tokens);
        const external = /^[a-z][a-z0-9+.-]*:/i.test(href);
        if (external) {
          return `<a class="lk lk-ext" href="${escapeHtml(href)}"` +
            ` rel="noopener noreferrer nofollow" target="_blank"` +
            `${title ? ` title="${escapeHtml(title)}"` : ''}>${text}</a>`;
        }
        // A relative markdown link is resolved through the same path as a
        // wikilink, so both agree with the index.
        const c = classify(decodeURIComponent(href));
        if (c.kind === 'ok') {
          return `<a class="lk lk-note" href="${hrefFor(c.path, c.anchor)}">${text}</a>`;
        }
        if (c.kind === 'redacted') {
          return `<span class="lk lk-locked" title="You do not have access to this note">${text}</span>`;
        }
        return `<span class="lk lk-dead" title="This note does not exist yet">${text}</span>`;
      },
      image({ href, title, text }) {
        const c = classify(decodeURIComponent(href));
        if (c.kind !== 'ok') {
          return `<span class="lk lk-dead">${escapeHtml(text || href)}</span>`;
        }
        return imgTag(c.path, text || c.title, title);
      },
    },
  });

  return {
    /** Render a note body as HTML for this viewer. */
    render(text, fromPath) {
      state.fromPath = fromPath;
      return marked.parse(text ?? '');
    },
    classify,
  };
}

function imgTag(path, alt, title) {
  return `<img class="asset" src="/_raw/${path.split('/').map(encodeURIComponent).join('/')}"` +
    ` alt="${escapeHtml(alt ?? '')}" loading="lazy"` +
    `${title ? ` title="${escapeHtml(title)}"` : ''}>`;
}

/**
 * An embed (`![[…]]`): an image inline, a note transcluded one level deep.
 *
 * Transclusion does not recurse. A note that embeds a note that embeds the
 * first would otherwise render forever, and vaults do contain that cycle.
 */
function renderEmbed(c, ctx) {
  if (IMAGE_EXT.has(extname(c.path))) {
    return `<figure class="embed-figure">${imgTag(c.path, c.alias ?? c.entry?.title)}` +
      (c.entry?.title ? `<figcaption>${escapeHtml(c.entry.title)}</figcaption>` : '') +
      `</figure>`;
  }

  const text = ctx.embedText?.(c.path);
  if (text == null) {
    return `<a class="lk lk-note" href="${hrefFor(c.path)}">${escapeHtml(c.title)}</a>`;
  }
  // Rendered with a nested renderer that refuses further embeds.
  const inner = createRenderer({ ...ctx, embedText: () => null });
  return `<blockquote class="transclusion">` +
    `<a class="transclusion-src" href="${hrefFor(c.path)}">${escapeHtml(c.title)}</a>` +
    inner.render(text, c.path) +
    `</blockquote>`;
}

function stripTags(html) {
  return String(html).replace(/<[^>]*>/g, '');
}

/** Headings of a rendered note, for the table of contents. */
export function tableOfContents(headings) {
  return (headings ?? [])
    .filter((h) => h.level >= 2 && h.level <= 3)
    .map((h) => ({ ...h, id: h.slug }));
}
