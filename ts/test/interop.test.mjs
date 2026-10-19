// The interop surfaces, INTEROP §§2–8.
//
// One suite per surface, each asking the question that surface exists to
// answer plus the one it is most likely to get wrong. The cross-protocol
// equivalence and leak checks live in equivalence.test.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { serve, VAULT, VAULT_ID } from './support/serve.mjs';
import { OPERATIONS } from '../src/serve/ops.mjs';
import { MCP_VERSIONS, MCP_LATEST } from '../src/serve/mcp.mjs';

// ---------------------------------------------------------------- discovery

test('discovery: one document names every mounted surface (§1.4)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/.well-known/basalt');
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.body.surfaces).sort(),
    ['connect', 'feeds', 'graphql', 'jsonrpc', 'mcp', 'rdf', 'rest', 'webdav']);
  assert.equal(r.body.vault.id, VAULT_ID);
  assert.deepEqual(r.body.operations, OPERATIONS.map((o) => o.name));

  // Mounting a subset must be visible in the document, or a client cannot
  // tell a surface that is off from one that is broken.
  const only = await serve({ surfaces: new Set(['rest', 'feeds']) });
  t.after(() => only.g.close());
  const d = await only.call('/.well-known/basalt');
  assert.deepEqual(Object.keys(d.body.surfaces).sort(), ['feeds', 'rest']);
  const gone = await only.call('/graphql?query={manifest{basalt}}', { principal: 'u:reader' });
  assert.equal(gone.status, 404);
});

test('discovery: the manifest bounds what may be mounted (§3.1, INTEROP §10)', async (t) => {
  // A vault owner takes a surface off for every deployment in one edit, the
  // same shape as the §12.2 audience ceiling.
  const bounded = await serve({
    interop: ['P-REST', 'P-MCP', 'P-INTEROP'], mountDeclared: true,
  });
  t.after(() => bounded.g.close());

  const d = await bounded.call('/.well-known/basalt');
  assert.deepEqual(Object.keys(d.body.surfaces).sort(), ['mcp', 'rest']);
  assert.equal((await bounded.call('/api/v1/manifest', { principal: 'u:reader' })).status, 200);
  assert.equal((await bounded.call('/graph.ttl', { principal: 'u:reader' })).status, 404);
  assert.equal((await bounded.call('/dav/', {
    principal: 'u:reader', method: 'PROPFIND', headers: { depth: '0' },
  })).status, 404);

  // A manifest that says nothing gets the §12 read surface and nothing else.
  // Profiles are opt-in (§14.1): silence means deny everywhere else in this
  // protocol, and a vault written before a profile existed cannot have
  // consented to serving it.
  const quiet = await serve({ mountDeclared: true });
  t.after(() => quiet.g.close());
  const all = await quiet.call('/.well-known/basalt');
  assert.deepEqual(Object.keys(all.body.surfaces).sort(), ['rest'],
    'a silent manifest must not mount interop profiles');

  // The operator can still ask for more; the vault just never implies it.
  const opted = await serve({ mountDeclared: true, surfaces: new Set(['rest', 'rdf']) });
  t.after(() => opted.g.close());
  assert.deepEqual(
    Object.keys((await opted.call('/.well-known/basalt')).body.surfaces).sort(),
    ['rdf', 'rest']);
});

// --------------------------------------------------------------------- REST

test('REST: the OpenAPI document describes every route it serves (§2)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/openapi.json');
  assert.equal(r.status, 200);
  assert.equal(r.body.openapi, '3.1.0');
  for (const route of ['/api/v1/node/{path}', '/api/v1/search', '/api/v1/effective',
    '/api/v1/raw/{path}', '/api/v1/tree', '/api/v1/nodes']) {
    assert.ok(r.body.paths[route], `${route} is undocumented`);
    const op = r.body.paths[route].get;
    // §12.3's two denials are a contract, not an implementation detail.
    assert.ok(op.responses[403] && op.responses[404], `${route} omits a denial`);
  }
  assert.ok(r.body.components.schemas.NodeEntry.properties.content_hash);
});

test('REST: conditional GET, and the etag is per principal (§12.5)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const first = await call('/api/v1/nodes', { principal: 'u:reader' });
  const etag = first.headers.get('etag');
  assert.ok(etag);

  const again = await call('/api/v1/nodes', {
    principal: 'u:reader', headers: { 'if-none-match': etag },
  });
  assert.equal(again.status, 304);

  // The owner sees one more node, so the same URL must not produce the same
  // validator — a shared cache keyed on the URL would hand the reader the
  // owner's body.
  const owner = await call('/api/v1/nodes', { principal: 'u:carter' });
  assert.notEqual(owner.headers.get('etag'), etag);
  const crossed = await call('/api/v1/nodes', {
    principal: 'u:carter', headers: { 'if-none-match': etag },
  });
  assert.equal(crossed.status, 200);
  assert.match(first.headers.get('cache-control'), /private/);
});

test('REST: denials are RFC 9457 problem documents', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const missing = await call('/api/v1/node/Notes%2FNope.md', { principal: 'u:reader' });
  assert.equal(missing.status, 404);
  assert.match(missing.headers.get('content-type'), /application\/problem\+json/);
  assert.equal(missing.body.type, 'urn:basalt:problem:not_found');
  // The legacy member stays, so a client written against the older surface
  // keeps working.
  assert.equal(missing.body.error, 'not_found');

  const head = await call('/api/v1/manifest', { principal: 'u:reader', method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.text, '');
  assert.ok(head.headers.get('etag'));
});

// ------------------------------------------------------------------ GraphQL

test('GraphQL: a query answers per principal, with denials as field errors (§3)', async (t) => {
  const { g, json } = await serve();
  t.after(() => g.close());

  const r = await json('/graphql', {
    query: `query Q($p: String!) {
      visible: node(path: $p) { title kind tags links { out { raw to } } }
      hidden: node(path: "Notes/Columns.md") { title }
      me { subjects }
    }`,
    variables: { p: 'Notes/Hexes.md' },
  }, 'u:reader');

  assert.equal(r.status, 200, 'a GraphQL denial is still a 200 with errors');
  assert.equal(r.body.data.visible.title, 'Hexagons');
  assert.equal(r.body.data.hidden, null);
  assert.equal(r.body.errors.length, 1);
  assert.equal(r.body.errors[0].extensions.code, 'forbidden');
  assert.deepEqual(r.body.errors[0].path, ['hidden']);
  // §9.5: the edge survives with the target withheld.
  const edge = r.body.data.visible.links.out.find((e) => e.raw === 'Columns');
  assert.equal(edge.to, 'redacted');
});

test('GraphQL: fragments, aliases, @skip, and the SDL it serves', async (t) => {
  const { g, call, json } = await serve();
  t.after(() => g.close());

  const r = await json('/graphql', {
    query: `{
      tree { ...T folders { ...T } }
      skipped: manifest @skip(if: true) { basalt }
      kept: manifest @include(if: true) { vaultId }
    }
    fragment T on TreeNode { folder entries { path } }`,
  }, 'u:reader');
  assert.equal(r.body.errors, undefined, JSON.stringify(r.body.errors));
  assert.equal(r.body.data.skipped, undefined);
  assert.equal(r.body.data.kept.vaultId, VAULT_ID);
  assert.ok(r.body.data.tree.folders.some((f) => f.folder === 'Notes/'));

  const get = await call('/graphql?query=' + encodeURIComponent('{ manifest { audience } }'),
    { principal: 'u:reader' });
  assert.equal(get.body.data.manifest.audience, 'gated');

  const sdl = await call('/graphql/schema.graphql');
  assert.match(sdl.headers.get('content-type'), /application\/graphql/);
  assert.match(sdl.text, /type Query \{/);
  assert.ok(!/type Mutation/.test(sdl.text), 'the read surface grew a Mutation type');

  const intro = await json('/graphql', {
    query: '{ __schema { queryType { name } types { name } } }',
  }, 'u:reader');
  assert.equal(intro.body.data.__schema.queryType.name, 'Query');
});

test('GraphQL: writes and unknown fields are refused before execution', async (t) => {
  const { g, json } = await serve();
  t.after(() => g.close());

  const mutation = await json('/graphql', { query: 'mutation { delete(path: "x") }' }, 'u:carter');
  assert.equal(mutation.body.data, undefined);
  assert.equal(mutation.body.errors[0].extensions.code, 'method_not_allowed');

  const typo = await json('/graphql', { query: '{ node(path: "a") { titel } }' }, 'u:carter');
  assert.match(typo.body.errors[0].message, /cannot query field "titel"/);
  assert.equal(typo.body.data, undefined, 'a validation failure must not execute anything');

  const missingArg = await json('/graphql', { query: '{ node { title } }' }, 'u:carter');
  assert.match(missingArg.body.errors[0].message, /argument "path" is required/);
});

// ----------------------------------------------------------------- JSON-RPC

test('JSON-RPC: the method table is the operation table (§4.1)', async (t) => {
  const { g, rpc } = await serve();
  t.after(() => g.close());

  const listed = await rpc('/rpc', 'basalt.operations', {}, 'u:reader');
  assert.deepEqual(listed.result.operations.map((o) => o.method),
    OPERATIONS.map((o) => `basalt.${o.name}`));

  const ok = await rpc('/rpc', 'basalt.search', { q: 'hexagons' }, 'u:reader');
  assert.equal(ok.result.query, 'hexagons');

  const denied = await rpc('/rpc', 'basalt.node', { path: 'Notes/Columns.md' }, 'u:reader');
  assert.equal(denied.error.data.status, 403);

  const missing = await rpc('/rpc', 'basalt.node', { path: 'Notes/Nope.md' }, 'u:reader');
  assert.equal(missing.error.data.status, 404);

  const unknown = await rpc('/rpc', 'basalt.drop_everything', {}, 'u:carter');
  assert.equal(unknown.error.code, -32601);
});

test('JSON-RPC: a notification gets no response body', async (t) => {
  const { g, json } = await serve();
  t.after(() => g.close());

  const r = await json('/rpc', { jsonrpc: '2.0', method: 'basalt.manifest' }, 'u:reader');
  assert.equal(r.status, 200);
  assert.equal(r.text, '');
});

// ---------------------------------------------------------------------- MCP

test('MCP: handshake, tools and resources (§4.2)', async (t) => {
  const { g, rpc } = await serve();
  t.after(() => g.close());

  const init = await rpc('/mcp', 'initialize', { protocolVersion: '2025-03-26' }, 'u:reader');
  assert.equal(init.result.protocolVersion, '2025-03-26', 'a supported version must be echoed');
  assert.ok(init.result.capabilities.tools);
  assert.ok(init.result.instructions.includes('access'));

  const future = await rpc('/mcp', 'initialize', { protocolVersion: '2099-01-01' }, 'u:reader');
  assert.equal(future.result.protocolVersion, MCP_LATEST);
  assert.ok(MCP_VERSIONS.includes(MCP_LATEST));

  const tools = await rpc('/mcp', 'tools/list', {}, 'u:reader');
  assert.deepEqual(tools.result.tools.map((x) => x.name),
    OPERATIONS.map((o) => `basalt_${o.name}`));
  for (const tool of tools.result.tools) {
    assert.equal(tool.inputSchema.type, 'object', `${tool.name} has no input schema`);
    assert.ok(tool.description, `${tool.name} has no description`);
  }

  const called = await rpc('/mcp', 'tools/call',
    { name: 'basalt_node', arguments: { path: 'Notes/Hexes.md' } }, 'u:reader');
  assert.equal(called.result.isError, undefined);
  assert.equal(JSON.parse(called.result.content[0].text).node.title, 'Hexagons');
});

test('MCP: a denial is a tool error, and resources carry the vault id', async (t) => {
  const { g, rpc } = await serve();
  t.after(() => g.close());

  const denied = await rpc('/mcp', 'tools/call',
    { name: 'basalt_node', arguments: { path: 'Notes/Columns.md' } }, 'u:reader');
  // A model asked a reasonable question; the answer is "you may not see that",
  // which belongs in the result where the model can read it.
  assert.equal(denied.result.isError, true);
  assert.equal(JSON.parse(denied.result.content[0].text).error, 'forbidden');

  const listed = await rpc('/mcp', 'resources/list', {}, 'u:reader');
  const uris = listed.result.resources.map((r) => r.uri);
  assert.ok(uris.every((u) => u.startsWith(`basalt://${VAULT_ID}/`)));
  assert.ok(!uris.some((u) => u.includes('Columns')), 'an unreadable node was advertised');

  const read = await rpc('/mcp', 'resources/read',
    { uri: `basalt://${VAULT_ID}/Notes/Start%20Here.md` }, 'u:reader');
  assert.match(read.result.contents[0].text, /Start/);
  assert.equal(read.result.contents[0].mimeType, 'text/markdown');

  const binary = await rpc('/mcp', 'resources/read',
    { uri: `basalt://${VAULT_ID}/Assets/diagram.png` }, 'u:reader');
  assert.ok(binary.result.contents[0].blob, 'a binary node must come back as a blob');

  // A client holding several vaults open must not cross them.
  const wrong = await rpc('/mcp', 'resources/read',
    { uri: 'basalt://SOMEOTHERVAULT/Notes/Hexes.md' }, 'u:reader');
  assert.ok(wrong.error, 'a foreign vault id was accepted');

  const withheld = await rpc('/mcp', 'resources/read',
    { uri: `basalt://${VAULT_ID}/index/nodes.json` }, 'u:carter');
  assert.equal(withheld.error.message, 'not_found');
});

// ------------------------------------------------------------------ Connect

test('Connect: POST and the idempotent GET form, with gRPC codes (§5)', async (t) => {
  const { g, call, json } = await serve();
  t.after(() => g.close());

  const post = await json('/basalt.v1.BasaltRead/GetNode', { path: 'Notes/Hexes.md' }, 'u:reader');
  assert.equal(post.status, 200);
  assert.equal(post.body.node.title, 'Hexagons');
  assert.equal(post.body.media_type, 'text/markdown; charset=utf-8',
    'the proto sets json_name so the wire shape matches every other surface');

  const message = encodeURIComponent(JSON.stringify({ path: 'Notes/Columns.md' }));
  const get = await call(
    `/basalt.v1.BasaltRead/GetNode?encoding=json&message=${message}&connect=v1`,
    { principal: 'u:reader' });
  assert.equal(get.status, 403);
  assert.equal(get.body.code, 'permission_denied');

  const missing = await json('/basalt.v1.BasaltRead/GetNode', { path: 'Nope.md' }, 'u:reader');
  assert.equal(missing.status, 404);
  assert.equal(missing.body.code, 'not_found');

  const unknown = await json('/basalt.v1.BasaltRead/DeleteEverything', {}, 'u:carter');
  assert.equal(unknown.status, 501);
  assert.equal(unknown.body.code, 'unimplemented');

  // Binary gRPC needs HTTP/2 and a proto codec; saying so beats failing to
  // parse protobuf as JSON.
  const binary = await call('/basalt.v1.BasaltRead/GetManifest', {
    principal: 'u:reader', method: 'POST',
    headers: { 'content-type': 'application/grpc+proto' }, body: '',
  });
  assert.equal(binary.status, 501);
  assert.match(binary.body.message, /application\/json/);
});

// ------------------------------------------------------------------- WebDAV

const hrefs = (xml) => [...xml.matchAll(/<D:href>([^<]*)<\/D:href>/g)]
  .map((m) => decodeURIComponent(m[1]));

test('WebDAV: a read-only mount, filtered per principal (§6)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const options = await call('/dav/', { principal: 'u:reader', method: 'OPTIONS' });
  assert.equal(options.status, 200);
  assert.match(options.headers.get('dav'), /1/);
  assert.equal(options.headers.get('allow'), 'OPTIONS, GET, HEAD, PROPFIND');

  const listing = await call('/dav/Notes/', {
    principal: 'u:reader', method: 'PROPFIND', headers: { depth: '1' },
  });
  assert.equal(listing.status, 207);
  const paths = hrefs(listing.text);
  assert.ok(paths.includes('/dav/Notes/Hexes.md'));
  assert.ok(!paths.some((p) => p.includes('Columns')),
    'an unreadable node appeared in a directory listing');

  const owner = await call('/dav/Notes/', {
    principal: 'u:carter', method: 'PROPFIND', headers: { depth: '1' },
  });
  assert.ok(hrefs(owner.text).some((p) => p.includes('Columns')));

  const file = await call('/dav/Notes/Hexes.md', {
    principal: 'u:reader', method: 'PROPFIND', headers: { depth: '0' },
  });
  assert.match(file.text, /<D:getcontentlength>\d+<\/D:getcontentlength>/);
  assert.match(file.text, /<D:getetag>/);

  const bytes = await call('/dav/Notes/Hexes.md', { principal: 'u:reader' });
  assert.equal(bytes.status, 200);
  assert.match(bytes.headers.get('content-type'), /text\/markdown/);

  for (const method of ['PUT', 'DELETE', 'MKCOL', 'MOVE', 'LOCK', 'PROPPATCH']) {
    const w = await call('/dav/Notes/New.md', { principal: 'u:carter', method });
    assert.equal(w.status, 405, `${method} was not refused`);
  }

  // §12.4: the protocol's own trees are not mountable either.
  const leak = await call('/dav/index/nodes.json', { principal: 'u:carter' });
  assert.equal(leak.status, 404);
});

// -------------------------------------------------------------------- feeds

test('feeds: Atom, RSS, sitemap and OpenSearch carry only readable nodes (§7)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const atom = await call('/feed.atom', { principal: 'u:reader' });
  assert.equal(atom.status, 200);
  assert.match(atom.headers.get('content-type'), /application\/atom\+xml/);
  assert.equal((atom.text.match(/<entry>/g) ?? []).length,
    (atom.text.match(/<\/entry>/g) ?? []).length);
  assert.match(atom.text, /<title>Hexagons<\/title>/);
  // No unreadable node may appear AS AN ENTRY. Its name may still appear
  // inside a summary when a readable note links to it in prose — that is the
  // author's own words in a node this principal may read, and §9.5 redacts
  // resolved targets, not the text that mentions them. Stripping it here
  // would be theatre: /api/v1/node returns the same sentence in full.
  const entries = [...atom.text.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map((m) => m[1]);
  assert.ok(entries.length > 0);
  for (const e of entries) {
    assert.ok(!/<link[^>]*href="[^"]*Columns/.test(e), 'a feed linked an unreadable node');
    assert.ok(!/<title>[^<]*Columns/.test(e), 'a feed listed an unreadable node');
  }
  // A feed is a filtered view, not a publication: an aggregator must not
  // share it between readers (§12.5).
  assert.match(atom.headers.get('cache-control'), /private/);

  const rss = await call('/feed.xml', { principal: 'u:reader' });
  assert.match(rss.text, /<rss version="2.0"/);
  assert.match(rss.text, /<guid isPermaLink="false">urn:basalt:node:/);

  const map = await call('/sitemap.xml', { principal: 'u:reader' });
  assert.match(map.text, /<loc>http:\/\/127\.0\.0\.1:\d+\/api\/v1\/node\/Notes\/Hexes\.md<\/loc>/);

  const search = await call('/opensearch.xml', { principal: 'u:reader' });
  assert.match(search.text, /template="[^"]*\/api\/v1\/search\?q=\{searchTerms\}"/);

  // §12.2: a gated vault asks crawlers to stay out wholesale, because every
  // path a crawler records is one a reader had to be granted.
  const robots = await call('/robots.txt', { principal: 'anonymous' });
  assert.match(robots.text, /Disallow: \/\n/);
  assert.match(robots.text, /audience=gated/);
});

// ---------------------------------------------------------------------- RDF

test('RDF: the graph is dereferenceable and redactions are counted (§8)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const ttl = await call('/graph.ttl', { principal: 'u:reader' });
  assert.equal(ttl.status, 200);
  assert.match(ttl.headers.get('content-type'), /text\/turtle/);
  assert.match(ttl.text, /@prefix basalt: <urn:basalt:v1:> \./);
  assert.ok(!ttl.text.includes('Columns.md'), 'the graph leaked an unreadable node');
  // Hexes links to Columns, which this principal may not see: the edge is not
  // emitted, but its existence is, so the published graph is not quietly wrong.
  assert.match(ttl.text, /basalt:redactedLinks "1"\^\^xsd:integer/);
  // Every statement block terminates.
  assert.equal((ttl.text.match(/ \.\n/g) ?? []).length >= 4, true);

  const ld = await call('/graph.jsonld', { principal: 'u:reader' });
  assert.equal(ld.status, 200);
  assert.match(ld.headers.get('content-type'), /application\/ld\+json/);
  assert.equal(ld.body['@context'].linksTo['@type'], '@id');
  const hexes = ld.body['@graph'].find((n) => n.path === 'Notes/Hexes.md');
  assert.equal(hexes.redactedLinks, 1);
  assert.ok(hexes.linksTo.some((iri) => iri.endsWith('/api/v1/node/Notes/Start%20Here.md')));
});

// ------------------------------------------------------- MCP over stdio

test('MCP: the stdio transport keeps stdout clean (§4.2)', async () => {
  // How an MCP client actually launches this: spawn the CLI, write
  // newline-delimited JSON-RPC, read it back. Anything but JSON-RPC on stdout
  // breaks the framing, so the startup line has to be on stderr.
  const { spawn } = await import('node:child_process');
  const cli = fileURLToPath(new URL('../bin/basalt.mjs', import.meta.url));
  const child = spawn(process.execPath, [cli, 'mcp', '--vault', VAULT, '--principal', 'u:reader'],
    { stdio: ['pipe', 'pipe', 'pipe'] });

  const lines = [];
  let buffer = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      lines.push(buffer.slice(0, nl));
      buffer = buffer.slice(nl + 1);
    }
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (c) => { stderr += c; });

  const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: MCP_LATEST } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'basalt_search', arguments: { q: 'hexagons' } } });
  send({ jsonrpc: '2.0', id: 3, method: 'resources/list' });

  const deadline = Date.now() + 10_000;
  while (lines.length < 3 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  child.stdin.end();
  child.kill();

  assert.equal(lines.length, 3, `expected 3 responses, got ${lines.length}: ${lines.join(' | ')}`);
  const parsed = lines.map((l) => JSON.parse(l));
  assert.equal(parsed[0].result.protocolVersion, MCP_LATEST);
  assert.equal(parsed[1].id, 2, 'the notification must not get a response');
  assert.equal(parsed[2].result.resources.length > 0, true);
  assert.match(stderr, /basalt mcp/);
});
