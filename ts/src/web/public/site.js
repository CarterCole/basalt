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
      for (const posting of idx.terms[term] ?? []) {
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
})();
