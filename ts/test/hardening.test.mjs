// Hostile input: notes, files, requests and queries written to do harm.
//
// Every case here once worked. Each either ran script in a reader's browser,
// took the server or the index down for everyone, or crossed a permission
// boundary, and each was found by an audit rather than by a test. They are
// kept together so the next change to the renderer, the router, the store or
// the indexer is checked against all of them at once.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import net from 'node:net';
import path from 'node:path';

import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { Gatekeeper } from '../src/gatekeeper.mjs';
import { ALL_SURFACES } from '../src/serve/router.mjs';
import { Surface } from '../src/serve/core.mjs';
import { graphql } from '../src/serve/graphql.mjs';
import { storeObject } from '../src/store.mjs';
import { parseNote } from '../src/frontmatter.mjs';
import { buildResolver } from '../src/links.mjs';
import { createRenderer } from '../src/web/markdown.mjs';
import { Site } from '../src/web/site.mjs';
import { exportSite, isInertSvg } from '../src/web/export.mjs';
import { corpusPath } from './support/spec.mjs';

const DEMO = corpusPath('vaults/demo/vault');
const MINIMAL = corpusPath('vaults/minimal/vault');
const SVG_NS = 'xmlns="http://www.w3.org/2000/svg"';

/** A scratch copy of a fixture; `prepare` may add files before it is indexed. */
async function scratch(t, fixture, prepare) {
  const dir = await mkdtemp(path.join(tmpdir(), 'basalt-hostile-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await cp(fixture, dir, { recursive: true });
  if (prepare) await prepare(dir);
  const v = new Vault(new FsTransport(dir));
  await v.load();
  await v.reindex();
  return { dir, v };
}

/** A bound note in a scratch vault's content tree. */
const note = (dir, rel, id, body) => writeFile(
  path.join(dir, 'content', rel), `---\nbasalt:\n  id: ${id}\n---\n${body}`);

async function listen(t, v, opts = {}) {
  const g = new Gatekeeper(v, {
    identify: (req) => req.headers['x-test-principal'] ?? 'anonymous',
    site: null,
    surfaces: new Set(ALL_SURFACES),
    ...opts,
  });
  await g.listen(0);
  t.after(() => g.close());
  const { port } = g.server.address();
  return { g, port, origin: `http://127.0.0.1:${port}` };
}

/** One raw request, for the things fetch() will not send. Resolves with the status line. */
const raw = (port, text) => new Promise((resolve) => {
  let buf = '';
  const s = net.connect(port, '127.0.0.1', () => s.write(text));
  s.setTimeout(5000, () => { s.destroy(); resolve('TIMEOUT'); });
  s.on('data', (c) => { buf += c; });
  s.on('error', () => resolve('ERROR'));
  s.on('close', () => resolve(buf.split('\r\n')[0] || 'NO RESPONSE'));
});

// ------------------------------------------------------------ the renderer

const renderer = () => createRenderer({
  resolver: buildResolver([]), canRead: () => true, byPath: new Map(), redactTitles: true,
});

test('render: text after an unclosed <script>, <style> or <textarea> is still escaped', () => {
  const r = renderer();
  for (const md of [
    'A sentence. <script> and later <img/src=x onerror="document.title=1"> end.',
    'Text <script> and here <script/src=/_raw/Geology/code.js> trailing.',
    '<style> x <svg/onload=alert(1)> y',
    '<textarea> <iframe/src=javascript:alert(1)>',
    '- item <script> then <img/src=x onerror=1>',
    '| a |\n|---|\n| <script> <img/src=x onerror=1> |',
    '# Heading <script> <img/src=x onerror=1>',
  ]) {
    const html = r.render(md, 'Notes/A.md');
    assert.doesNotMatch(html, /<(img|script|svg|iframe|style|textarea)\b/i, md);
    assert.match(html, /&lt;/, md);
  }
});

test('render: ordinary text is escaped once, not twice', () => {
  const html = renderer().render('AT&amp;T, 5 < 6 & "quoted"', 'Notes/A.md');
  assert.equal(html.trim(), '<p>AT&amp;T, 5 &lt; 6 &amp; &quot;quoted&quot;</p>');
});

test('render: a link that would run script is shown as text, and a bad escape does not throw', () => {
  const html = renderer().render(
    '[a](javascript:alert(1)) [b](DATA:text/html,x) [c](vbscript:x) <javascript:alert(1)> '
    + '[ok](https://example.com/?a=1&b=2) [bad](x#%zz) ![bad](%zz.png)', 'Notes/A.md');
  assert.doesNotMatch(html, /href="(javascript|data|vbscript):/i);
  assert.match(html, /href="https:\/\/example\.com\/\?a=1&amp;b=2"/);
});

// ------------------------------------------------- author bytes on the site

test('site: a stored script, stylesheet or page is never served as one, and an SVG is sandboxed', async (t) => {
  const { v } = await scratch(t, DEMO, async (dir) => {
    const g = path.join(dir, 'content/Geology');
    await writeFile(path.join(g, 'code.js'), 'document.title = "js"');
    await writeFile(path.join(g, 'look.css'), 'body { display: none }');
    await writeFile(path.join(g, 'page.html'), '<script>document.title = "html"</script>');
    await writeFile(path.join(g, 'pic.svg'), `<svg ${SVG_NS}><script>document.title = "svg"</script></svg>`);
    await writeFile(path.join(g, 'doc.pdf'), '%PDF-1.4\n');
  });
  const { origin } = await listen(t, v, { site: new Site(v) });
  const head = async (p) => (await fetch(origin + p)).headers;

  for (const p of ['/_raw/Geology/code.js', '/_raw/Geology/look.css', '/_raw/Geology/page.html',
    '/Geology/code.js', '/Geology/page.html']) {
    const h = await head(p);
    assert.equal(h.get('content-type'), 'application/octet-stream', p);
    assert.equal(h.get('x-content-type-options'), 'nosniff', p);
    assert.match(h.get('content-security-policy'), /\bsandbox\b/, p);
  }
  for (const p of ['/_raw/Geology/pic.svg', '/Geology/pic.svg', '/api/v1/raw/Geology/pic.svg', '/dav/Geology/pic.svg']) {
    const h = await head(p);
    assert.equal(h.get('content-type'), 'image/svg+xml', p);
    assert.match(h.get('content-security-policy'), /default-src 'none'.*\bsandbox\b/, p);
    assert.doesNotMatch(h.get('content-security-policy'), /script-src/, p);
  }
  // A PDF is shown by the browser's own viewer, which a sandbox would stop.
  const pdf = await head('/_raw/Geology/doc.pdf');
  assert.equal(pdf.get('content-type'), 'application/pdf');
  assert.doesNotMatch(pdf.get('content-security-policy') ?? '', /\bsandbox\b/);
  // The site's own script is still script.
  assert.match((await head('/_assets/site.js')).get('content-type'), /^text\/javascript/);
});

// --------------------------------------------------------- the static export

test('export: an SVG is published only when it is nothing but a drawing', async () => {
  assert.equal(isInertSvg(await readFile(path.join(DEMO, 'content/Assets/hexagons.svg'))), true);
  const refused = [
    `<svg ${SVG_NS}><script>alert(1)</script></svg>`,
    `<svg ${SVG_NS} xmlns:x="http://www.w3.org/1999/xhtml"><x:script>alert(1)</x:script></svg>`,
    `<svg ${SVG_NS} onload="alert(1)"/>`,
    `<svg ${SVG_NS}><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject></svg>`,
    `<svg ${SVG_NS}><a href="javascript:alert(1)"><text>x</text></a></svg>`,
    `<svg ${SVG_NS}><use href="https://evil.example/x.svg#a"/></svg>`,
    `<svg ${SVG_NS} xmlns:z="http://www.w3.org/1999/xlink"><use z:href="evil.svg#a"/></svg>`,
    `<svg ${SVG_NS}><image href="data:image/svg+xml;base64,AAAA"/></svg>`,
    `<svg ${SVG_NS}><image href="&#104;ttps://evil.example/t.png"/></svg>`,
    `<svg ${SVG_NS}><set attributeName="href" to="javascript:alert(1)"/></svg>`,
    `<!DOCTYPE svg [<!ENTITY x "<script>alert(1)</script>">]><svg ${SVG_NS}>&x;</svg>`,
    `<?xml version="1.0"?><?xml-stylesheet href="x.xsl" type="text/xsl"?><svg ${SVG_NS}/>`,
    `<svg ${SVG_NS}><style><![CDATA[ x ]]></style></svg>`,
    `<svg ${SVG_NS} onload=alert(1)/>`,
    `<html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>`,
    `<svg ${SVG_NS}/><script`,
  ];
  for (const svg of refused) assert.equal(isInertSvg(Buffer.from(svg)), false, svg);
  assert.equal(isInertSvg(Buffer.from([0xff, 0xfe, 0x3c, 0x00])), false);
  const kept = [
    `<?xml version="1.0" encoding="UTF-8"?>\n<svg ${SVG_NS} viewBox="0 0 9 9"><title>t</title><!-- c --><g fill="red"><rect width="1" height="1"/></g></svg>`,
    `<svg ${SVG_NS} xmlns:xlink="http://www.w3.org/1999/xlink"><defs><circle id="c" r="2"/></defs><use xlink:href="#c"/></svg>`,
    `<svg ${SVG_NS}><style>text{font:10px sans-serif}</style><text x="1" y="2">5 &lt; 6 &amp; ok</text></svg>`,
    `<svg ${SVG_NS}><image href="data:image/png;base64,iVBORw0KGgo=" width="1" height="1"/></svg>`,
  ];
  for (const svg of kept) assert.equal(isInertSvg(Buffer.from(svg)), true, svg);
});

test('export: nothing a browser would run is written, and a hostile note is only text', async (t) => {
  const { v } = await scratch(t, DEMO, async (dir) => {
    const g = path.join(dir, 'content/Geology');
    await note(dir, 'Geology/Field Trip.md', '01jbq9d3m0000000000000xss1',
      '# Field trip\n\nA sentence. <script> and later <img/src=x onerror="document.title=1"> end.\n\n'
      + '[click](javascript:alert(1))\n');
    await writeFile(path.join(g, 'page.html'), '<script>document.title = "html"</script>');
    await writeFile(path.join(g, 'feed.xml'), '<x xmlns="http://www.w3.org/1999/xhtml"><script>1</script></x>');
    await writeFile(path.join(g, 'pic.svg'), `<svg ${SVG_NS}><script>document.title = "svg"</script></svg>`);
    await writeFile(path.join(g, 'code.js'), 'document.title = "js"');
  });
  const out = await mkdtemp(path.join(tmpdir(), 'basalt-hostile-out-'));
  t.after(() => rm(out, { recursive: true, force: true }));
  const logged = [];
  await exportSite({ vault: v, out, clean: true, log: (m) => logged.push(m) });

  for (const name of ['page.html', 'feed.xml', 'pic.svg']) {
    assert.ok(!existsSync(path.join(out, 'Geology', name)), `${name} at its own path`);
    assert.ok(!existsSync(path.join(out, '_raw/Geology', name)), `${name} under _raw`);
    assert.ok(logged.some((m) => m.includes('not exported') && m.includes(name)), `${name} is reported`);
  }
  // A drawing, and the demo vault's own SVG, still go out.
  assert.ok(existsSync(path.join(out, '_raw/Assets/hexagons.svg')));
  const page = await readFile(path.join(out, 'Geology/Field Trip/index.html'), 'utf8');
  const prose = page.slice(page.indexOf('A sentence.'));
  assert.doesNotMatch(prose.slice(0, 400), /<img\b/i);
  assert.doesNotMatch(page, /href="javascript:/i);
});

// ------------------------------------------------------------ the listener

test('serve: a request that does not parse is a 400, and the server keeps answering', async (t) => {
  const { v } = await scratch(t, MINIMAL);
  const { port, origin } = await listen(t, v);
  const died = [];
  const onRejection = (err) => died.push(err);
  process.on('unhandledRejection', onRejection);
  t.after(() => process.off('unhandledRejection', onRejection));

  for (const request of [
    'GET // HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n',
    'GET /api/v1/manifest HTTP/1.1\r\nHost: [\r\nConnection: close\r\n\r\n',
    'GET /api/v1/manifest HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n',
    'GET /api/v1/manifest HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-Proto: 1\r\nConnection: close\r\n\r\n',
  ]) {
    assert.match(await raw(port, request), /^HTTP\/1\.1 400 /, JSON.stringify(request));
  }
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(died, []);
  assert.equal((await fetch(`${origin}/api/v1/manifest`)).status, 200);
});

test('serve: a handler that throws answers 500 instead of rejecting', async (t) => {
  const { v } = await scratch(t, MINIMAL);
  const { origin } = await listen(t, v, { identify: () => { throw new Error('boom'); } });
  assert.equal((await fetch(`${origin}/api/v1/manifest`)).status, 500);
});

// --------------------------------------------------------------- the store

test('store: a multi-line title is a title, never more frontmatter', async (t) => {
  const { dir, v } = await scratch(t, MINIMAL);
  // u:editor may create in Notes/ but holds no write_acl there.
  assert.equal(v.can('u:editor', 'Notes/', ['create_child']).allowed, true);
  assert.equal(v.can('u:editor', 'Notes/', ['write_acl']).allowed, false);
  const victim = v.indexes.nodes.entries.find((e) => e.path === 'Notes/Columns.md').id;
  const title = [
    'a: b', 'k: &b basalt', '*b :', `  id: ${victim}`,
    '  created_by: {principal: "u:carter", agent: forged}',
    '  acl:', '    owner: u:editor', '    dacl:',
    '      - {type: allow, subject: u:editor, rights: [full_control], flags: []}',
    '      - {type: allow, subject: everyone, rights: [read, publish], flags: []}',
  ].join('\n');
  const r = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Attack.md', bytes: Buffer.from('body\n'), title, provenance: {},
  });

  const text = await readFile(path.join(dir, 'content/Notes/Attack.md'), 'utf8');
  const parsed = parseNote(text, 'Notes/Attack.md');
  assert.equal(parsed.id, r.id);
  assert.equal(parsed.acl, null);
  assert.equal(parsed.title, title.replace(/\s+$/, ''));
  assert.deepEqual(Object.keys(parsed.frontmatter).sort(), ['basalt', 'title']);
  assert.equal(parsed.frontmatter.basalt.created_by.principal, 'u:editor');

  const again = new Vault(new FsTransport(dir));
  await again.load();
  await again.reindex();
  assert.equal(again.can('u:editor', 'Notes/Attack.md', ['write_acl']).allowed, false);
  assert.equal(again.indexes.nodes.entries.find((e) => e.path === 'Notes/Columns.md').id, victim);
});

test('store: no stored object can stop the vault from indexing', async (t) => {
  const { dir, v } = await scratch(t, DEMO);
  const objects = [
    ['Drafts/t1.md', '# hi\n\ntext #constructor #toString #valueOf #hasOwnProperty\n'],
    ['Drafts/t2.md', '---\ntags: [__proto__, constructor]\n---\nbody\n'],
    ['Drafts/t3.md', '[x](Note.md#%E0%A4%A) [y](%zz#%zz) [z](a%2)\n'],
    ['Drafts/a.json', '['.repeat(20000) + ']'.repeat(20000)],
    ['Drafts/b.json', '{"a":'.repeat(5000) + '1' + '}'.repeat(5000)],
    ['Drafts/constructor.md', 'see [[constructor]] and [[__proto__]] and [[toString]]\n'],
    ['Drafts/__proto__', 'bytes'],
    ['Drafts/constructor', 'bytes'],
    ['Drafts/hasOwnProperty/toString', 'bytes'],
    ['Drafts/__proto__x/__proto__/valueOf.md', 'body #__proto__\n'],
    ['Drafts/d.yaml', '__proto__: {link: "[[t1]]"}\nconstructor: [1]\nlinks: ["[[constructor]]"]\n'],
  ];
  for (const [p, body] of objects) {
    await storeObject(v, { path: p, bytes: Buffer.from(body) });
  }
  // What a fresh `basalt serve` or `basalt mcp` does at startup.
  const fresh = new Vault(new FsTransport(dir));
  await fresh.load();
  await fresh.reindex({ force: true });
  const tags = fresh.indexes.tags.entries;
  for (const tag of ['constructor', '__proto__', 'toString']) {
    assert.ok(Object.hasOwn(tags, tag) && Array.isArray(tags[tag]), `tag ${tag} is indexed`);
  }
  const surface = new Surface(fresh, {});
  assert.equal(fresh.search('u:carter', 'constructor __proto__ toString').status, 200);
  assert.ok(surface.nodes('u:carter').length >= objects.length);
  assert.equal(fresh.links('u:carter', 'Drafts/t3.md').status, 200);
});

// ----------------------------------------------------------------- GraphQL

test('graphql: a query is refused once it asks for more than one request may', async (t) => {
  const { v } = await scratch(t, DEMO);
  const surface = new Surface(v, {});
  const ask = (source) => graphql({ source, surface, principal: 'anonymous' });

  // Each level doubles the work: 60 levels is 2^60 visits, in under 3 KB.
  let fan = 'query { ...F0 } ';
  for (let i = 0; i < 60; i++) fan += `fragment F${i} on Query { ...F${i + 1} ...F${i + 1} } `;
  fan += 'fragment F60 on Query { __typename }';
  const started = Date.now();
  const refused = await ask(fan);
  assert.ok(Date.now() - started < 2000, 'refused promptly');
  assert.equal(refused.data, null);
  assert.equal(refused.errors.length, 1);
  assert.match(refused.errors[0].message, /too much/);

  for (const cycle of [
    'query { ...A } fragment A on Query { ...A }',
    'query { ...A } fragment A on Query { ...B } fragment B on Query { ...A __typename }',
  ]) {
    const r = await ask(cycle);
    assert.equal(r.data, undefined);
    assert.match(r.errors[0].message, /spreads itself/);
  }

  // A member of Object.prototype is not a field or a fragment.
  assert.match((await ask('{ constructor }')).errors[0].message, /cannot query field/);
  assert.match((await ask('{ ...toString }')).errors[0].message, /unknown fragment/);

  // An ordinary query, with a fragment used twice, is untouched.
  const ok = await ask('query { a: manifest { ...M } b: manifest { ...M } } fragment M on Manifest { title }');
  assert.equal(ok.errors, undefined);
  assert.equal(ok.data.a.title, ok.data.b.title);
});

// ------------------------------------------------- a case-folding filesystem

test('fs: a folder spelled so that only the filesystem thinks it exists is refused', async (t) => {
  const { dir, v } = await scratch(t, MINIMAL, async (d) => {
    await mkdir(path.join(d, 'content/Site'), { recursive: true });
    await mkdir(path.join(d, 'meta/acl/Site'), { recursive: true });
    await note(d, 'Site/Home.md', '01jbq7x8z4n3vyk9m2t5hrwc7a', '# Home\n');
    await writeFile(path.join(d, 'meta/acl/acl.yaml'), [
      'folder:', '  owner: u:carter', '  dacl:',
      '    - {type: allow, subject: everyone, rights: [traverse, list], flags: [ci]}',
      '    - {type: allow, subject: g:editors, rights: [create_child], flags: [ci]}', '',
    ].join('\n'));
    await writeFile(path.join(d, 'meta/acl/Site/acl.yaml'), [
      'folder:', '  owner: u:carter', '  protected: true', '  dacl:',
      '    - {type: allow, subject: u:carter, rights: [full_control], flags: [ci, oi]}',
      '    - {type: allow, subject: everyone, rights: [read, publish, list, traverse], flags: [ci, oi]}', '',
    ].join('\n'));
  });
  // U+017F, long s: lowercases to itself, so §2.2 sees a new folder, while
  // APFS and NTFS open `Site`.
  if (!existsSync(path.join(dir, 'content/ſite'))) {
    t.skip('this filesystem does not fold case');
    return;
  }
  const put = (p) => storeObject(v, {
    principal: 'u:editor', path: p, bytes: Buffer.from('# Planted\n'), provenance: {},
  });
  await assert.rejects(put('Site/Planted.md'), /create_child is required/);
  await assert.rejects(put('ſite/Planted.md'), /same folder as Site\//);
  assert.deepEqual(await readdir(path.join(dir, 'content/Site')), ['Home.md']);
});
