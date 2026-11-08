// Progressive enhancement for the Basalt publish site.
//
// Every page is fully readable server-rendered with this file absent: the nav
// tree is <details>, the TOC is plain anchors, and search degrades to a form
// that posts to /_search. Nothing here is required to read a note.

(() => {
  'use strict';

  // ------------------------------------------------------------- theme
  const THEME_KEY = 'basalt.theme';
  const root = document.documentElement;

  const readTheme = () => {
    try { return localStorage.getItem(THEME_KEY); } catch { return null; }
  };
  const writeTheme = (v) => {
    try { v ? localStorage.setItem(THEME_KEY, v) : localStorage.removeItem(THEME_KEY); }
    catch { /* private window, blocked storage — the page still works */ }
  };

  const stored = readTheme();
  if (stored === 'light' || stored === 'dark') root.dataset.theme = stored;

  const toggle = document.querySelector('[data-theme-toggle]');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const dark = root.dataset.theme
        ? root.dataset.theme === 'dark'
        : matchMedia('(prefers-color-scheme: dark)').matches;
      const next = dark ? 'light' : 'dark';
      root.dataset.theme = next;
      writeTheme(next);
      toggle.setAttribute('aria-label', `Switch to ${dark ? 'dark' : 'light'} theme`);
    });
  }

  // ------------------------------------------------------------- pdf embeds
  // A browser with no inline PDF viewer shows the <object> fallback; size the
  // box to that one line rather than a page-tall empty frame. Undefined in
  // older browsers, which all have a viewer, so only `false` counts.
  if (navigator.pdfViewerEnabled === false) root.classList.add('no-pdf-viewer');

  // ------------------------------------------------------------- sidebar
  const sidebar = document.querySelector('[data-sidebar]');
  const navBtn = document.querySelector('[data-nav-toggle]');
  if (sidebar && navBtn) {
    navBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      sidebar.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('open') &&
          !sidebar.contains(e.target) && e.target !== navBtn) {
        sidebar.classList.remove('open');
      }
    });
  }

  // ------------------------------------------------------------- search
  const input = document.querySelector('[data-search]');
  const panel = document.querySelector('[data-search-results]');

  // A statically exported site has no server to query, so the postings ship
  // with the page. The exported index contains PUBLIC nodes only (§12.6), so
  // searching it in the browser discloses nothing that is not already served.
  const isStatic = !!document.querySelector('meta[name="basalt-static"]');
  const basePath = (() => {
    const link = document.querySelector('link[rel="stylesheet"]');
    const href = link?.getAttribute('href') ?? '/_assets/site.css';
    return href.slice(0, href.indexOf('/_assets/')) || '';
  })();

  let staticIndex = null;
  const loadStaticIndex = async () => {
    if (staticIndex) return staticIndex;
    const res = await fetch(`${basePath}/_assets/search-index.json`);
    staticIndex = await res.json();
    return staticIndex;
  };

  const searchStatic = async (q) => {
    const idx = await loadStaticIndex();
    const byId = new Map(idx.nodes.map((n) => [n.id, n]));
    const scores = new Map();
    for (const term of q.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? []) {
      for (const posting of (Object.hasOwn(idx.terms, term) ? idx.terms[term] : [])) {
        scores.set(posting.node, (scores.get(posting.node) ?? 0) + posting.tf);
      }
    }
    return [...scores.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([id]) => byId.get(id))
      .filter(Boolean);
  };

  if (input && panel) {
    let timer = null;
    let lastQuery = '';

    const clear = () => { panel.innerHTML = ''; panel.classList.remove('open'); };

    const run = async (q) => {
      if (q.length < 2) return clear();
      if (q === lastQuery) return;
      lastQuery = q;
      try {
        let data;
        if (isStatic) {
          data = { hits: await searchStatic(q) };
        } else {
          const res = await fetch(`/_search.json?q=${encodeURIComponent(q)}`, {
            headers: { accept: 'application/json' },
          });
          if (!res.ok) return clear();
          data = await res.json();
        }
        // Server results are filtered per principal (§12.5) and static ones
        // were filtered at export; the client never holds a posting it may
        // not see.
        if (!data.hits || !data.hits.length) {
          panel.innerHTML = '<p class="search-empty">No matches.</p>';
          panel.classList.add('open');
          return;
        }
        panel.innerHTML = data.hits.slice(0, 12).map((h) =>
          `<a class="search-hit" href="${h.href}">${escape(h.title)}` +
          `<span class="search-hit-path">${escape(h.path)}</span></a>`,
        ).join('');
        panel.classList.add('open');
      } catch { clear(); }
    };

    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      timer = setTimeout(() => run(q), 140);
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { input.value = ''; clear(); input.blur(); }
      if (e.key === 'ArrowDown') {
        const first = panel.querySelector('.search-hit');
        if (first) { e.preventDefault(); first.focus(); }
      }
    });

    // "/" focuses search, the one shortcut worth having.
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement !== input &&
          !/^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName ?? '')) {
        e.preventDefault();
        input.focus();
      }
    });
  }

  function escape(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  // ------------------------------------------------------------- toc spy
  const tocLinks = [...document.querySelectorAll('.toc a[href^="#"]')];
  const headings = tocLinks
    .map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1))))
    .filter(Boolean);

  if (headings.length && 'IntersectionObserver' in window) {
    const seen = new Set();
    const mark = () => {
      // The topmost heading that has been scrolled past wins.
      let active = null;
      for (const h of headings) {
        if (h.getBoundingClientRect().top <= 96) active = h;
      }
      active ??= headings[0];
      for (const a of tocLinks) {
        a.classList.toggle('active',
          decodeURIComponent(a.hash.slice(1)) === active.id);
      }
    };
    const io = new IntersectionObserver(() => mark(), {
      rootMargin: '-80px 0px -70% 0px',
    });
    for (const h of headings) io.observe(h);
    addEventListener('scroll', mark, { passive: true });
    mark();
  }

  // ------------------------------------------------------------- diagrams
  // A ```mermaid block is readable as code without this. Pages that have one
  // load the vendored Mermaid bundle (about 5 MB, so only those pages) and
  // swap each block for its drawing. securityLevel 'strict' is Mermaid's
  // default, set anyway: diagram source is vault content, so it must not run
  // script or carry click handlers. A block Mermaid cannot parse, or a
  // bundle that fails to load, leaves the source showing.
  const diagrams = [...document.querySelectorAll('pre > code.language-mermaid')]
    .map((code) => ({ pre: code.parentElement, source: code.textContent, figure: null, sheet: null }));

  if (diagrams.length) {
    const prefersDark = matchMedia('(prefers-color-scheme: dark)');
    const isDark = () => (root.dataset.theme
      ? root.dataset.theme === 'dark' : prefersDark.matches);

    let bundle = null;
    const loadMermaid = () => (bundle ??= new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = `${basePath}/_assets/vendor/mermaid.min.js`;
      s.onload = () => (window.mermaid ? resolve(window.mermaid) : reject(new Error('no mermaid')));
      s.onerror = reject;
      document.head.append(s);
    }));

    // The site's Content-Security-Policy admits no <style> element and no
    // style="" attribute, and Mermaid's SVG carries both, so as inserted it
    // draws every shape solid black. Styles set through the CSSOM are not
    // subject to style-src, so move them there: the <style> text into a
    // constructed sheet, each style attribute into element.style.
    const adoptStyles = (d) => {
      const svg = d.figure.querySelector('svg');
      if (!svg) return;
      if (d.sheet) {
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== d.sheet);
        d.sheet = null;
      }
      const css = [...svg.querySelectorAll('style')]
        .map((s) => { const text = s.textContent; s.remove(); return text; })
        .join('\n');
      if (css && 'adoptedStyleSheets' in document) {
        try {
          const sheet = new CSSStyleSheet();
          sheet.replaceSync(css);
          document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
          d.sheet = sheet;
        } catch { /* an older browser: shapes keep their default fill */ }
      }
      for (const el of [svg, ...svg.querySelectorAll('[style]')]) {
        const inline = el.getAttribute('style');
        if (inline) el.style.cssText = inline;
      }
    };

    let seq = 0;
    const draw = async () => {
      let mermaid;
      try { mermaid = await loadMermaid(); } catch { return; }
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        suppressErrorRendering: true,
        theme: isDark() ? 'dark' : 'default',
      });
      for (const d of diagrams) {
        try {
          const { svg } = await mermaid.render(`basalt-diagram-${++seq}`, d.source);
          if (!d.figure) {
            d.figure = document.createElement('figure');
            d.figure.className = 'diagram';
            d.pre.replaceWith(d.figure);
          }
          d.figure.innerHTML = svg;
          adoptStyles(d);
        } catch { /* invalid diagram: its source stays on the page */ }
      }
    };

    draw();
    // Redraw in the other palette when the reader switches theme.
    toggle?.addEventListener('click', draw);
    prefersDark.addEventListener?.('change', () => { if (!root.dataset.theme) draw(); });
  }
})();
