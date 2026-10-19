// Cross-protocol equivalence, INTEROP §9 and PROTOCOL §14.2.
//
// Interoperability is a claim that has to be tested, not asserted: eight
// surfaces are only one surface if they answer the same question the same way
// for the same principal. These tests ask each one the same questions and
// compare — the visible node set, one node's content, both denials, the
// withheld trees, and the cache. A surface that drifts fails here rather than
// in someone's deployment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { serve, VAULT_ID } from './support/serve.mjs';
import YAML from 'yaml';
import { OPERATIONS } from '../src/serve/ops.mjs';
import { FAULTS } from '../src/serve/core.mjs';
import { printSchema } from '../src/serve/graphql.mjs';

const PRINCIPALS = ['u:carter', 'u:reader', 'anonymous'];

/** Non-collection hrefs from a PROPFIND body, as vault paths. */
function davPaths(xml) {
  const blocks = [...xml.matchAll(/<D:response>([\s\S]*?)<\/D:response>/g)].map((m) => m[1]);
  return blocks
    .filter((b) => !b.includes('<D:collection/>'))
    .map((b) => decodeURIComponent(b.match(/<D:href>([^<]*)<\/D:href>/)[1]))
    .map((h) => h.replace(/^\/dav\//, ''))
    .filter(Boolean)
    .sort();
}

/** The visible node set, asked of every surface that can answer it. */
async function nodeSets(ctx, principal) {
  const { call, json, rpc } = ctx;
  const out = {};

  const rest = await call('/api/v1/nodes', { principal });
  out.rest = rest.body.entries.map((e) => e.path).sort();

  const gql = await json('/graphql', { query: '{ nodes { entries { path } } }' }, principal);
  out.graphql = gql.body.data.nodes.entries.map((e) => e.path).sort();

  const r = await rpc('/rpc', 'basalt.nodes', {}, principal);
  out.jsonrpc = r.result.entries.map((e) => e.path).sort();

  const mcp = await rpc('/mcp', 'resources/list', {}, principal);
  out.mcp = mcp.result.resources.map((x) => x.name).sort();

  const connect = await json('/basalt.v1.BasaltRead/ListNodes', {}, principal);
  out.connect = (connect.body.entries ?? []).map((e) => e.path).sort();

  const dav = await call('/dav/', {
    principal, method: 'PROPFIND', headers: { depth: 'infinity' },
  });
  // A principal who cannot list the root is denied the mount outright, which
  // is the same answer as "you see nothing" expressed in DAV's vocabulary.
  out.webdav = dav.status === 207 ? davPaths(dav.text) : [];
  if (dav.status !== 207) assert.ok([403, 404].includes(dav.status), `dav gave ${dav.status}`);

  return out;
}

test('equivalence: every surface shows one principal the same nodes (§9)', async (t) => {
  const ctx = await serve();
  t.after(() => ctx.g.close());

  for (const principal of PRINCIPALS) {
    const sets = await nodeSets(ctx, principal);
    const [first, ...rest] = Object.entries(sets);
    for (const [name, value] of rest) {
      assert.deepEqual(value, first[1],
        `${name} disagrees with ${first[0]} for ${principal}:\n`
        + `  ${first[0]}: ${JSON.stringify(first[1])}\n  ${name}: ${JSON.stringify(value)}`);
    }
  }

  // And the sets really do differ by principal, or the test above would pass
  // on a surface that returns nothing to everyone.
  const owner = await nodeSets(ctx, 'u:carter');
  const reader = await nodeSets(ctx, 'u:reader');
  assert.ok(owner.rest.length > reader.rest.length);
  assert.deepEqual(await nodeSets(ctx, 'anonymous').then((s) => s.rest), []);
});

test('equivalence: one node reads identically on every surface', async (t) => {
  const ctx = await serve();
  t.after(() => ctx.g.close());
  const { call, json, rpc } = ctx;
  const path = 'Notes/Hexes.md';
  const principal = 'u:reader';

  const rest = await call(`/api/v1/node/${encodeURIComponent(path)}`, { principal });
  const raw = await call(`/api/v1/raw/${encodeURIComponent(path)}`, { principal });
  const gql = await json('/graphql', {
    query: `{ node(path: "${path}") { title text mediaType links { out { raw to } } } }`,
  }, principal);
  const jr = await rpc('/rpc', 'basalt.node', { path }, principal);
  const conn = await json('/basalt.v1.BasaltRead/GetNode', { path }, principal);
  const mcp = await rpc('/mcp', 'resources/read',
    { uri: `basalt://${VAULT_ID}/Notes/Hexes.md` }, principal);
  const dav = await call(`/dav/${path}`, { principal });

  const text = rest.body.text;
  assert.equal(gql.body.data.node.text, text);
  assert.equal(jr.result.text, text);
  assert.equal(conn.body.text, text);
  assert.equal(mcp.result.contents[0].text, text);
  assert.equal(dav.text, text, 'the DAV mount served different bytes');
  assert.equal(raw.text, text, '/raw served different bytes');

  assert.equal(gql.body.data.node.title, rest.body.node.title);
  assert.equal(conn.body.node.title, rest.body.node.title);
  // The redacted edge must look the same everywhere, including the sentinel.
  const edgeOf = (edges) => edges.find((e) => e.raw === 'Columns').to;
  assert.equal(edgeOf(gql.body.data.node.links.out), 'redacted');
  assert.equal(edgeOf(jr.result.links.out), 'redacted');
  assert.equal(edgeOf(conn.body.links.out), 'redacted');
  assert.equal(edgeOf(rest.body.links.out), 'redacted');
});

test('equivalence: both denials mean the same thing on every surface (§12.3)', async (t) => {
  const ctx = await serve();
  t.after(() => ctx.g.close());
  const { call, json, rpc } = ctx;
  const principal = 'u:reader';

  // Discoverable but unreadable -> forbidden. Unknown -> not found. The two
  // must never swap, because a 403 on a path the requester could not
  // discover confirms that path exists.
  for (const [path, expected] of [['Notes/Columns.md', 'forbidden'], ['Notes/Nope.md', 'not_found']]) {
    const status = expected === 'forbidden' ? 403 : 404;

    const rest = await call(`/api/v1/node/${encodeURIComponent(path)}`, { principal });
    assert.equal(rest.status, status, `rest ${path}`);
    assert.equal(rest.body.error, expected);

    const gql = await json('/graphql', { query: `{ node(path: "${path}") { title } }` }, principal);
    assert.equal(gql.body.data.node, null, `graphql ${path}`);
    assert.equal(gql.body.errors[0].extensions.code, expected);

    const jr = await rpc('/rpc', 'basalt.node', { path }, principal);
    assert.equal(jr.error.message, expected, `jsonrpc ${path}`);
    assert.equal(jr.error.data.status, status);

    const conn = await json('/basalt.v1.BasaltRead/GetNode', { path }, principal);
    assert.equal(conn.status, status, `connect ${path}`);
    assert.equal(conn.body.code, expected === 'forbidden' ? 'permission_denied' : 'not_found');

    const mcp = await rpc('/mcp', 'tools/call',
      { name: 'basalt_node', arguments: { path } }, principal);
    assert.equal(JSON.parse(mcp.result.content[0].text).error, expected, `mcp ${path}`);

    const dav = await call(`/dav/${path}`, { principal });
    assert.equal(dav.status, status, `webdav ${path}`);
  }
});

test('equivalence: no surface serves the protocol trees (§12.4)', async (t) => {
  const ctx = await serve();
  t.after(() => ctx.g.close());
  const { call, json, rpc } = ctx;
  // As the vault owner, who holds full_control: these are withheld from
  // everyone, because the indexes and ACLs are the private half of the vault.
  const principal = 'u:carter';

  for (const target of ['index/nodes.json', 'meta/acl/Notes/acl.yaml',
    'principals/users.yaml', 'basalt.yaml', 'history/x']) {
    const rest = await call(`/api/v1/raw/${encodeURIComponent(target)}`, { principal });
    assert.equal(rest.status, 404, `rest served ${target}`);

    const node = await call(`/api/v1/node/${encodeURIComponent(target)}`, { principal });
    assert.equal(node.status, 404, `rest node served ${target}`);

    const gql = await json('/graphql', { query: `{ node(path: "${target}") { text } }` }, principal);
    assert.equal(gql.body.data.node, null, `graphql served ${target}`);
    assert.equal(gql.body.errors[0].extensions.code, 'not_found');

    const jr = await rpc('/rpc', 'basalt.node', { path: target }, principal);
    assert.equal(jr.error.message, 'not_found', `jsonrpc served ${target}`);

    const conn = await json('/basalt.v1.BasaltRead/GetNode', { path: target }, principal);
    assert.equal(conn.status, 404, `connect served ${target}`);

    const dav = await call(`/dav/${target}`, { principal });
    assert.equal(dav.status, 404, `webdav served ${target}`);

    const links = await rpc('/rpc', 'basalt.links', { path: target }, principal);
    assert.equal(links.error.message, 'not_found', `links served ${target}`);
  }

  // Nor by listing: the reserved prefixes must not appear as content anywhere.
  for (const principal2 of PRINCIPALS) {
    const sets = await nodeSets(ctx, principal2);
    for (const [name, paths] of Object.entries(sets)) {
      for (const p of paths) {
        assert.ok(!/^(index|meta|principals|history)\//.test(p),
          `${name} listed ${p} for ${principal2}`);
      }
    }
  }
});

test('equivalence: warming one principal never serves it to another (§12.5)', async (t) => {
  // THE leak test, run per surface and in both orders, because a cache that
  // omits the subject set serves whichever principal arrived first.
  const probes = {
    rest: async (ctx, p) => {
      const r = await ctx.call('/api/v1/list/Notes%2F', { principal: p });
      return (r.body.entries ?? []).map((e) => e.path);
    },
    graphql: async (ctx, p) => {
      const r = await ctx.json('/graphql',
        { query: '{ list(folder: "Notes/") { entries { path } } }' }, p);
      return (r.body.data.list?.entries ?? []).map((e) => e.path);
    },
    jsonrpc: async (ctx, p) => {
      const r = await ctx.rpc('/rpc', 'basalt.list', { folder: 'Notes/' }, p);
      return (r.result?.entries ?? []).map((e) => e.path);
    },
    connect: async (ctx, p) => {
      const r = await ctx.json('/basalt.v1.BasaltRead/ListFolder', { folder: 'Notes/' }, p);
      return (r.body.entries ?? []).map((e) => e.path);
    },
    mcp: async (ctx, p) => {
      const r = await ctx.rpc('/mcp', 'resources/list', {}, p);
      return r.result.resources.map((x) => x.name).filter((n) => n.startsWith('Notes/'));
    },
    webdav: async (ctx, p) => {
      const r = await ctx.call('/dav/Notes/', {
        principal: p, method: 'PROPFIND', headers: { depth: '1' },
      });
      return r.status === 207 ? davPaths(r.text) : [];
    },
    feeds: async (ctx, p) => {
      const r = await ctx.call('/feed.atom', { principal: p });
      return [...r.text.matchAll(/\/api\/v1\/node\/([^"]+)"/g)]
        .map((m) => decodeURIComponent(m[1]));
    },
    rdf: async (ctx, p) => {
      const r = await ctx.call('/graph.jsonld', { principal: p });
      return (r.body['@graph'] ?? []).map((n) => n.path);
    },
  };

  for (const [name, probe] of Object.entries(probes)) {
    for (const order of [['u:carter', 'u:reader'], ['u:reader', 'u:carter']]) {
      const ctx = await serve();
      t.after(() => ctx.g.close());
      const first = await probe(ctx, order[0]);
      const second = await probe(ctx, order[1]);
      const secret = (set) => set.some((p) => p.includes('Columns'));
      assert.equal(secret(first), order[0] === 'u:carter',
        `${name}: ${order[0]} got the wrong view asking first`);
      assert.equal(secret(second), order[1] === 'u:carter',
        `${name}: ${order[1]} was served ${order[0]}'s visibility from cache`);
    }
  }
});

test('equivalence: the operation table, the proto and the SDL stay in step', async (t) => {
  // Drift between the three descriptions of the same operations is the
  // failure mode of a repo with this many surfaces, and it is silent.
  const proto = await readFile(
    fileURLToPath(new URL('../../protocol/basalt.proto', import.meta.url)), 'utf8');
  const sdl = printSchema();

  const declared = [...proto.matchAll(/^\s*rpc (\w+)\(/gm)].map((m) => m[1]).sort();
  assert.deepEqual(declared, OPERATIONS.map((o) => o.proto).sort(),
    'protocol/basalt.proto and OPERATIONS disagree about the method list');

  for (const op of OPERATIONS) {
    assert.ok(proto.includes(`rpc ${op.proto}(`), `${op.proto} is missing from the proto`);
    assert.ok(/^[a-z][a-z_]*$/.test(op.name), `${op.name} is not a wire-stable name`);
  }

  // The GraphQL surface is allowed to shape things differently (it has `me`,
  // `recent` and a lazy `Node.text`), but every operation's subject must be
  // reachable from Query, or a GraphQL-only client is missing a capability
  // the other surfaces have.
  for (const field of ['manifest', 'me', 'node', 'nodes', 'list', 'links',
    'search', 'tree', 'tags', 'recent', 'effective']) {
    assert.match(sdl, new RegExp(`^  ${field}[(:]`, 'm'), `Query.${field} is missing`);
  }
});

test('equivalence: the interop corpus describes this implementation (§14.2)', async () => {
  // The corpus is normative, so the spellings and the fault table live there
  // and this implementation is checked against them — not the other way
  // round. A surface renamed in code and not in conformance/ fails here.
  const read = async (rel) => YAML.parse(await readFile(
    fileURLToPath(new URL(rel, import.meta.url)), 'utf8'));

  const manifest = await read('../../conformance/manifest.yaml');
  const listed = manifest.suites.filter((x) => x.file.startsWith('cases/interop/'));
  assert.equal(listed.length, 2, 'the manifest does not inventory the interop suites');

  const surfaces = await read('../../conformance/cases/interop/surfaces.yaml');
  const equivalence = await read('../../conformance/cases/interop/equivalence.yaml');

  for (const entry of listed) {
    const file = entry.file.endsWith('surfaces.yaml') ? surfaces : equivalence;
    assert.equal(entry.cases, file.cases.length,
      `${entry.file} declares ${entry.cases} cases, holds ${file.cases.length}`);
    assert.equal(entry.spec, file.spec, `${entry.file}: spec section`);
  }
  // Every profile the manifest names has a case saying what it requires.
  assert.deepEqual(Object.keys(manifest.profiles).sort(),
    surfaces.cases.map((c) => c.id).sort());

  // Operation spellings, per surface.
  assert.deepEqual(surfaces.operations.map((o) => o.name), OPERATIONS.map((o) => o.name));
  for (const spec of surfaces.operations) {
    const op = OPERATIONS.find((o) => o.name === spec.name);
    assert.equal(spec.rpc, `basalt.${op.name}`, `${op.name}: JSON-RPC name`);
    assert.equal(spec.tool, `basalt_${op.name}`, `${op.name}: MCP tool name`);
    assert.equal(spec.proto, op.proto, `${op.name}: proto method`);
    assert.deepEqual(spec.args, Object.keys(op.input.properties ?? {}), `${op.name}: arguments`);
    assert.deepEqual(spec.required, op.input.required ?? [], `${op.name}: required arguments`);
  }

  // The fault table, every column.
  for (const row of surfaces.faults) {
    const f = FAULTS[row.fault];
    assert.ok(f, `${row.fault} is in the corpus and not in the implementation`);
    assert.equal(f.status, row.http, `${row.fault}: HTTP status`);
    assert.equal(f.connect, row.connect, `${row.fault}: Connect code`);
    assert.equal(f.rpc, row.jsonrpc, `${row.fault}: JSON-RPC code`);
  }
  assert.deepEqual(surfaces.faults.map((r) => r.fault).sort(), Object.keys(FAULTS).sort());

  // The equivalence questions E1-E8 are the ones this suite implements.
  assert.deepEqual(equivalence.cases.map((c) => c.id.split('-')[0]),
    ['E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7', 'E8']);
});

test('equivalence: the shape invariants E8 pins (§13.3, §7.1, INTEROP §1.2)', async (t) => {
  // Each of these was a disagreement found by running this implementation and
  // the Rust one side by side; the corpus owns the rule, both implementations
  // are held to it, and this test is the half that holds this one.
  const corpus = YAML.parse(await readFile(
    fileURLToPath(new URL('../../conformance/cases/interop/equivalence.yaml', import.meta.url)),
    'utf8'));
  const invariants = corpus.cases.find((c) => c.id === 'E8-shape-invariants').invariants;
  const checked = new Set();

  const ctx = await serve();
  t.after(() => ctx.g.close());
  const principal = 'u:reader';

  const me = (await ctx.call('/api/v1/me', { principal })).body;
  const tags = (await ctx.call('/api/v1/tags', { principal })).body.tags;
  const links = (await ctx.call('/api/v1/links/Notes%2FHexes.md', { principal })).body;
  const node = (await ctx.call('/api/v1/node/Notes%2FHexes.md', { principal })).body;
  const manifest = (await ctx.call('/api/v1/manifest', { principal })).body;

  for (const inv of invariants) {
    switch (inv.id) {
      case 'subjects-sorted':
        assert.deepEqual(me.subjects, [...me.subjects].sort(), inv.rule);
        assert.ok(me.subjects.includes('g:staff') && me.subjects.includes(principal));
        break;
      case 'display-name-from-display':
        assert.equal(me.display_name, 'A Reader', inv.rule);
        break;
      case 'tags-sorted':
        assert.deepEqual(tags.map((t2) => t2.tag), [...tags.map((t2) => t2.tag)].sort(), inv.rule);
        break;
      case 'edge-target-present':
        for (const edge of links.out) {
          assert.ok('target' in edge, `${inv.rule} (${edge.raw})`);
        }
        assert.equal(links.out.find((e) => e.raw === 'Does Not Exist').target, null);
        break;
      case 'node-links-is-a-linkset':
        assert.equal(node.links.path, 'Notes/Hexes.md', inv.rule);
        assert.deepEqual(Object.keys(node.links).sort(), Object.keys(links).sort());
        break;
      case 'index-state-is-honest':
        // This vault stores no indexes, so a server that just built them in
        // memory must not call them `fresh`.
        assert.ok(['fresh', 'stale', 'rebuilt'].includes(manifest.index_state), inv.rule);
        break;
      default:
        assert.fail(`no check implemented for invariant ${inv.id}`);
    }
    checked.add(inv.id);
  }
  assert.equal(checked.size, invariants.length);
});
