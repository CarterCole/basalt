// The GraphQL surface, INTEROP §3.
//
// Hand-written rather than pulled from npm, for the same reason the canonical
// JSON writer is: the schema is a cross-language artifact. `basalt schema
// graphql` prints SDL from the type table below, a Python or Rust
// implementation serves that same SDL with whatever library it likes, and the
// equivalence suite (§14.2) checks all of them answer identically. A
// dependency would make the reference implementation's behaviour the spec.
//
// Supported: queries, variables, aliases, named and inline fragments,
// @skip/@include, and introspection sufficient for client codegen. Not
// supported, deliberately: mutations and subscriptions (the gatekeeper is
// read-only, §12), interfaces, unions and custom directives.

import { RIGHTS } from '../acl.mjs';
import { Fault } from './core.mjs';

export class GraphQLError extends Error {
  constructor(message, { path, code = 'bad_request' } = {}) {
    super(message);
    this.name = 'GraphQLError';
    this.path = path;
    this.code = code;
  }
}

// ----------------------------------------------------------- type references
//
// Field types are written as SDL strings ("[Hit!]!") instead of composed
// objects: one spelling for the runtime, the printer and the documentation.

export function parseRef(s) {
  const t = s.trim();
  if (t.endsWith('!')) return { kind: 'NON_NULL', ofType: parseRef(t.slice(0, -1)) };
  if (t.startsWith('[') && t.endsWith(']')) return { kind: 'LIST', ofType: parseRef(t.slice(1, -1)) };
  if (!/^[_A-Za-z][_0-9A-Za-z]*$/.test(t)) throw new GraphQLError(`bad type reference ${JSON.stringify(s)}`);
  return { kind: 'NAMED', name: t };
}

const printRef = (ref) => ref.kind === 'NON_NULL' ? printRef(ref.ofType) + '!'
  : ref.kind === 'LIST' ? '[' + printRef(ref.ofType) + ']'
    : ref.name;

const namedOf = (ref) => ref.kind === 'NAMED' ? ref.name : namedOf(ref.ofType);

// ------------------------------------------------------------------- lexer

const PUNCT = '!$():=@[]{|}';

function lex(src) {
  const out = [];
  let i = 0;
  const bad = (m) => new GraphQLError(`syntax error: ${m}`);
  while (i < src.length) {
    const c = src[i];
    if (c === '﻿' || c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') { i++; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (src.startsWith('...', i)) { out.push({ t: '...' }); i += 3; continue; }
    if (PUNCT.includes(c)) { out.push({ t: c }); i++; continue; }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_0-9A-Za-z]/.test(src[j])) j++;
      out.push({ t: 'Name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[-0-9]/.test(c)) {
      let j = i;
      if (src[j] === '-') j++;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      let float = false;
      if (src[j] === '.') { float = true; j++; while (j < src.length && /[0-9]/.test(src[j])) j++; }
      if (src[j] === 'e' || src[j] === 'E') {
        float = true; j++;
        if (src[j] === '+' || src[j] === '-') j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      out.push({ t: float ? 'Float' : 'Int', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        if (end === -1) throw bad('unterminated block string');
        out.push({ t: 'String', v: dedent(src.slice(i + 3, end)) });
        i = end + 3;
        continue;
      }
      let j = i + 1;
      let s = '';
      const ESC = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\n') throw bad('unterminated string');
        if (src[j] === '\\') {
          const e = src[j + 1];
          if (e === 'u') { s += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16)); j += 6; continue; }
          if (!(e in ESC)) throw bad(`bad escape \\${e}`);
          s += ESC[e]; j += 2; continue;
        }
        s += src[j++];
      }
      if (j >= src.length) throw bad('unterminated string');
      out.push({ t: 'String', v: s });
      i = j + 1;
      continue;
    }
    throw bad(`unexpected character ${JSON.stringify(c)}`);
  }
  out.push({ t: 'EOF' });
  return out;
}

function dedent(block) {
  const lines = block.split('\n');
  let indent = Infinity;
  for (const line of lines.slice(1)) {
    const m = line.match(/^[ \t]*/)[0].length;
    if (line.trim() !== '') indent = Math.min(indent, m);
  }
  if (indent !== Infinity) {
    for (let i = 1; i < lines.length; i++) lines[i] = lines[i].slice(indent);
  }
  while (lines.length && lines[0].trim() === '') lines.shift();
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
  return lines.join('\n');
}

// ------------------------------------------------------------------ parser

export function parse(source) {
  const toks = lex(source);
  let i = 0;
  const peek = () => toks[i];
  const at = (t, v) => peek().t === t && (v === undefined || peek().v === v);
  const next = () => toks[i++];
  const expect = (t, v) => {
    if (!at(t, v)) {
      throw new GraphQLError(`syntax error: expected ${v ?? t}, found ${peek().v ?? peek().t}`);
    }
    return next();
  };

  const value = (constOnly) => {
    const k = peek();
    if (k.t === '$') {
      next();
      const name = expect('Name').v;
      if (constOnly) throw new GraphQLError('a variable is not allowed here');
      return { kind: 'variable', name };
    }
    if (k.t === 'Int') { next(); return { kind: 'int', value: parseInt(k.v, 10) }; }
    if (k.t === 'Float') { next(); return { kind: 'float', value: parseFloat(k.v) }; }
    if (k.t === 'String') { next(); return { kind: 'string', value: k.v }; }
    if (k.t === 'Name') {
      next();
      if (k.v === 'true' || k.v === 'false') return { kind: 'boolean', value: k.v === 'true' };
      if (k.v === 'null') return { kind: 'null', value: null };
      return { kind: 'enum', value: k.v };
    }
    if (k.t === '[') {
      next();
      const items = [];
      while (!at(']')) items.push(value(constOnly));
      expect(']');
      return { kind: 'list', value: items };
    }
    if (k.t === '{') {
      next();
      const fields = {};
      while (!at('}')) {
        const name = expect('Name').v;
        expect(':');
        fields[name] = value(constOnly);
      }
      expect('}');
      return { kind: 'object', value: fields };
    }
    throw new GraphQLError(`syntax error: unexpected ${k.v ?? k.t} in a value`);
  };

  const args = () => {
    if (!at('(')) return {};
    next();
    const out = {};
    while (!at(')')) {
      const name = expect('Name').v;
      expect(':');
      out[name] = value(false);
    }
    expect(')');
    return out;
  };

  const directives = () => {
    const out = [];
    while (at('@')) {
      next();
      out.push({ name: expect('Name').v, args: args() });
    }
    return out;
  };

  const typeRef = () => {
    let ref;
    if (at('[')) {
      next();
      ref = { kind: 'LIST', ofType: typeRef() };
      expect(']');
    } else {
      ref = { kind: 'NAMED', name: expect('Name').v };
    }
    if (at('!')) { next(); ref = { kind: 'NON_NULL', ofType: ref }; }
    return ref;
  };

  const selectionSet = () => {
    expect('{');
    const sels = [];
    while (!at('}')) {
      if (at('...')) {
        next();
        if (at('Name') && peek().v !== 'on') {
          const name = next().v;
          sels.push({ kind: 'spread', name, directives: directives() });
          continue;
        }
        let typeCondition = null;
        if (at('Name', 'on')) { next(); typeCondition = expect('Name').v; }
        const dirs = directives();
        sels.push({ kind: 'inline', typeCondition, directives: dirs, selections: selectionSet() });
        continue;
      }
      let name = expect('Name').v;
      let alias = null;
      if (at(':')) { next(); alias = name; name = expect('Name').v; }
      const a = args();
      const dirs = directives();
      const sub = at('{') ? selectionSet() : null;
      sels.push({ kind: 'field', name, alias, args: a, directives: dirs, selections: sub });
    }
    expect('}');
    return sels;
  };

  const operations = [];
  const fragments = {};
  while (!at('EOF')) {
    if (at('{')) {
      operations.push({ type: 'query', name: null, vars: [], directives: [], selections: selectionSet() });
      continue;
    }
    const kw = expect('Name').v;
    if (kw === 'fragment') {
      const name = expect('Name').v;
      expect('Name', 'on');
      const typeCondition = expect('Name').v;
      const dirs = directives();
      fragments[name] = { name, typeCondition, directives: dirs, selections: selectionSet() };
      continue;
    }
    if (kw !== 'query' && kw !== 'mutation' && kw !== 'subscription') {
      throw new GraphQLError(`syntax error: unexpected ${kw}`);
    }
    const name = at('Name') ? next().v : null;
    const vars = [];
    if (at('(')) {
      next();
      while (!at(')')) {
        expect('$');
        const vname = expect('Name').v;
        expect(':');
        const vtype = typeRef();
        let def;
        if (at('=')) { next(); def = value(true); }
        vars.push({ name: vname, type: vtype, defaultValue: def });
      }
      expect(')');
    }
    operations.push({ type: kw, name, vars, directives: directives(), selections: selectionSet() });
  }
  if (!operations.length) throw new GraphQLError('the document contains no operation');
  return { operations, fragments };
}

// ------------------------------------------------------------------ schema

const scalar = (name, description, serialize) => ({ kind: 'SCALAR', name, description, serialize });
const enumType = (name, description, values) => ({
  kind: 'ENUM', name, description, values: values.map((v) => ({ name: v })),
});
const object = (name, description, fields) => ({ kind: 'OBJECT', name, description, fields });

const str = (v) => v === null || v === undefined ? null : String(v);
const int = (v) => {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  if (!Number.isInteger(n)) throw new GraphQLError(`Int cannot represent ${JSON.stringify(v)}`);
  return n;
};

/** A Node resolver source: the index entry, plus the read result if loaded. */
const nodeSrc = (entry, loaded = null) => ({ entry, loaded });

async function loadNode(src, ctx) {
  if (!src.loaded) src.loaded = await ctx.surface.node(ctx.principal, src.entry.path);
  return src.loaded;
}

const SCALARS = {
  String: scalar('String', null, str),
  ID: scalar('ID', null, str),
  Int: scalar('Int', null, int),
  Boolean: scalar('Boolean', null, (v) => v === null || v === undefined ? null : Boolean(v)),
  Float: scalar('Float', null, (v) => v === null || v === undefined ? null : Number(v)),
};

const DOMAIN = {
  Right: enumType('Right', 'A right from §8.1. Spelled exactly as the ACL files spell it.', RIGHTS),
  Grant: enumType('Grant', 'The outcome of an ACL evaluation (§8.4).', ['allow', 'deny']),
  Audience: enumType('Audience', 'The vault-wide ceiling from §12.2.', ['public', 'gated', 'private']),
  IndexState: enumType('IndexState', 'Index freshness (§10.6).', ['fresh', 'stale', 'rebuilt']),
  NodeKind: enumType('NodeKind', 'Kind, a function of the key alone (§5.1).',
    ['note', 'data', 'asset', 'opaque']),
  LinkKind: enumType('LinkKind', 'A recognized link form (§9.1).',
    ['wiki', 'embed', 'md', 'external', 'tag']),

  Manifest: object('Manifest', 'The public subset of the manifest (§3.1).', {
    basalt: { type: 'Int!' },
    vaultId: { type: 'ID!', resolve: (m) => m.vault.id },
    title: { type: 'String', resolve: (m) => m.vault.title },
    audience: { type: 'Audience!', resolve: (m) => m.publish.audience },
    home: { type: 'String', resolve: (m) => m.publish.home },
    indexState: { type: 'IndexState!', resolve: (m) => m.index_state },
  }),

  Identity: object('Identity', 'The principal this request reduced to (§12.1).', {
    principal: { type: 'ID!' },
    displayName: { type: 'String', resolve: (i) => i.display_name },
    subjects: { type: '[String!]!', description: 'The subject set used by §8.4 step 1.' },
    anonymous: { type: 'Boolean!' },
  }),

  Heading: object('Heading', 'A heading, as anchors resolve against it (§9.3).', {
    level: { type: 'Int!' }, slug: { type: 'String!' }, text: { type: 'String!' },
  }),

  Node: object('Node',
    'A node. Scalar fields come from index/nodes.json; `text`, `base64` and '
    + '`mtime` are read on demand and re-checked against §8.4, so asking for '
    + 'them across a large selection costs one store read each.', {
      path: { type: 'String!', resolve: (s) => s.entry.path },
      id: { type: 'ID!', resolve: (s) => s.entry.id },
      kind: { type: 'NodeKind!', resolve: (s) => s.entry.kind },
      title: { type: 'String!', resolve: (s) => s.entry.title },
      size: { type: 'Int!', resolve: (s) => s.entry.size ?? 0 },
      contentHash: { type: 'String!', resolve: (s) => s.entry.content_hash },
      etag: { type: 'String', resolve: (s) => s.entry.etag ?? null },
      publish: { type: 'Boolean!', resolve: (s) => s.entry.publish !== false },
      tags: { type: '[String!]!', resolve: (s) => s.entry.tags ?? [] },
      aliases: { type: '[String!]!', resolve: (s) => s.entry.aliases ?? [] },
      headings: { type: '[Heading!]!', resolve: (s) => s.entry.headings ?? [] },
      errors: { type: '[String!]!', resolve: (s) => s.entry.errors ?? [] },
      mediaType: {
        type: 'String!',
        resolve: async (s, _a, ctx) => (await loadNode(s, ctx)).media_type,
      },
      text: {
        type: 'String',
        description: 'UTF-8 text, or null for a kind that has none.',
        resolve: async (s, _a, ctx) => (await loadNode(s, ctx)).text,
      },
      base64: {
        type: 'String',
        description: 'The raw bytes, base64-encoded. Never presigned (§12.4).',
        resolve: async (s, _a, ctx) => {
          const r = await loadNode(s, ctx);
          return r.bytes ? Buffer.from(r.bytes).toString('base64') : null;
        },
      },
      mtime: {
        type: 'String',
        description: 'Store mtime, when the store reports one. Never load-bearing (§1).',
        resolve: async (s, _a, ctx) => (await ctx.surface.stat(ctx.principal, s.entry.path)).mtime,
      },
      links: {
        type: 'LinkSet',
        resolve: (s, _a, ctx) => ctx.surface.links(ctx.principal, s.entry.path),
      },
    }),

  Entry: object('Entry', 'A reference to a node, as listings and backlinks carry it.', {
    id: { type: 'ID!' },
    path: { type: 'String', description: 'Null when the reference is redacted (§9.5).' },
    title: { type: 'String' },
    kind: { type: 'NodeKind' },
    node: {
      type: 'Node',
      description: 'The full node, if still readable. Null for a redacted reference.',
      resolve: async (e, _a, ctx) => {
        if (!e.path) return null;
        const r = await ctx.surface.node(ctx.principal, e.path);
        return nodeSrc(r.node, r);
      },
    },
  }),

  LinkEdge: object('LinkEdge',
    'An out-edge. `to: "redacted"` is §9.5: the edge is kept so the graph '
    + 'stays honest, with the target withheld.', {
      from: { type: 'ID!' },
      to: { type: 'String' },
      kind: { type: 'LinkKind!' },
      raw: { type: 'String!' },
      alias: { type: 'String' },
      anchor: { type: 'String' },
      anchorResolved: { type: 'Boolean', resolve: (e) => e.anchor_resolved ?? null },
      ambiguous: { type: 'Boolean!', resolve: (e) => e.ambiguous ?? false },
      candidates: { type: '[String!]!', resolve: (e) => e.candidates ?? [] },
      line: { type: 'Int!' }, col: { type: 'Int!' },
      target: { type: 'Entry' },
    }),

  LinkSet: object('LinkSet', 'Out-edges and backlinks for one node (§10.2, §10.3).', {
    path: { type: 'String!' },
    out: { type: '[LinkEdge!]!' },
    backlinks: { type: '[Entry!]!' },
  }),

  FolderListing: object('FolderListing', 'Direct entries of a folder (§12.3).', {
    folder: { type: 'String!' },
    entries: { type: '[Entry!]!' },
    folders: { type: '[String!]!' },
  }),

  NodeCatalogue: object('NodeCatalogue', 'A page of readable nodes, in §13.3 order.', {
    total: { type: 'Int!' },
    offset: { type: 'Int!' },
    limit: { type: 'Int!' },
    entries: { type: '[Node!]!', resolve: (c) => c.entries.map((e) => nodeSrc(e)) },
  }),

  Hit: object('Hit', 'A search posting, filtered to readable nodes (§12.5).', {
    score: { type: 'Int!' },
    node: { type: 'Node!', resolve: (h) => nodeSrc(h) },
  }),

  SearchResult: object('SearchResult', null, {
    query: { type: 'String!' },
    total: { type: 'Int!' },
    offset: { type: 'Int!' },
    hits: { type: '[Hit!]!' },
  }),

  TreeNode: object('TreeNode', 'The navigable tree, pruned to what is visible (§12.3).', {
    folder: { type: 'String!' },
    title: { type: 'String!' },
    entries: { type: '[Entry!]!' },
    folders: { type: '[TreeNode!]!' },
  }),

  TagPosting: object('TagPosting', 'A tag and the readable nodes carrying it (§9.6).', {
    tag: { type: 'String!' },
    nodes: { type: '[Entry!]!' },
  }),

  Decision: object('Decision', 'One right, and the ACE that decided it (§8.7).', {
    right: { type: 'Right!' },
    decision: { type: 'Grant!' },
    by: { type: 'String!' },
    failedAt: { type: 'String', resolve: (d) => d.failed_at ?? null },
  }),

  Effective: object('Effective', 'Effective rights. Requires `read_acl` (§8.7).', {
    principal: { type: 'ID!' },
    path: { type: 'String!' },
    granted: { type: '[Right!]!' },
    decisions: {
      type: '[Decision!]!',
      resolve: (e) => Object.entries(e.decisions).map(([right, d]) => ({ right, ...d })),
    },
    failedAt: { type: 'String', resolve: (e) => e.failed_at ?? null },
  }),
};

const QUERY = object('Query',
  'Every field is evaluated for the requesting principal (§8.4). A field the '
  + 'principal may not see resolves to null with an error carrying '
  + '`extensions.code`; `not_found` covers both "no such object" and "you may '
  + 'not discover it", which §12.3 requires be indistinguishable.', {
    manifest: { type: 'Manifest!', resolve: (_s, _a, ctx) => ctx.surface.manifest() },
    me: { type: 'Identity!', resolve: (_s, _a, ctx) => ctx.surface.me(ctx.principal) },
    node: {
      type: 'Node',
      args: { path: { type: 'String!' } },
      resolve: async (_s, { path }, ctx) => {
        const r = await ctx.surface.node(ctx.principal, path);
        return nodeSrc(r.node, r);
      },
    },
    nodes: {
      type: 'NodeCatalogue!',
      args: {
        limit: { type: 'Int', defaultValue: 100 },
        offset: { type: 'Int', defaultValue: 0 },
        published: { type: 'Boolean', defaultValue: false },
      },
      resolve: (_s, { limit, offset, published }, ctx) => {
        const all = ctx.surface.nodes(ctx.principal, { publishedOnly: published });
        const n = Math.min(1000, Math.max(1, limit ?? 100));
        const from = Math.max(0, offset ?? 0);
        return { total: all.length, offset: from, limit: n, entries: all.slice(from, from + n) };
      },
    },
    list: {
      type: 'FolderListing',
      args: { folder: { type: 'String', defaultValue: '' } },
      resolve: (_s, { folder }, ctx) => ctx.surface.list(ctx.principal, folder ?? ''),
    },
    links: {
      type: 'LinkSet',
      args: { path: { type: 'String!' } },
      resolve: (_s, { path }, ctx) => ctx.surface.links(ctx.principal, path),
    },
    search: {
      type: 'SearchResult',
      args: {
        q: { type: 'String!' },
        limit: { type: 'Int', defaultValue: 20 },
        offset: { type: 'Int', defaultValue: 0 },
      },
      resolve: (_s, { q, limit, offset }, ctx) =>
        ctx.surface.search(ctx.principal, q, { limit, offset }),
    },
    tree: { type: 'TreeNode', resolve: (_s, _a, ctx) => ctx.surface.tree(ctx.principal) },
    tags: { type: '[TagPosting!]!', resolve: (_s, _a, ctx) => ctx.surface.tags(ctx.principal) },
    recent: {
      type: '[Node!]!',
      description: 'Readable nodes by store mtime, newest first — the feed view.',
      args: {
        limit: { type: 'Int', defaultValue: 20 },
        published: { type: 'Boolean', defaultValue: true },
      },
      resolve: async (_s, { limit, published }, ctx) => {
        const rows = await ctx.surface.recent(ctx.principal, { limit, publishedOnly: published });
        return rows.map((e) => nodeSrc(e));
      },
    },
    effective: {
      type: 'Effective',
      args: { path: { type: 'String!' }, principal: { type: 'String' } },
      resolve: (_s, { path, principal }, ctx) =>
        ctx.surface.effective(ctx.principal, { path, principal: principal ?? undefined }),
    },
  });

// ----------------------------------------------------------- introspection

const INTROSPECTION = {
  __TypeKind: enumType('__TypeKind', null,
    ['SCALAR', 'OBJECT', 'INTERFACE', 'UNION', 'ENUM', 'INPUT_OBJECT', 'LIST', 'NON_NULL']),
  __DirectiveLocation: enumType('__DirectiveLocation', null,
    ['QUERY', 'MUTATION', 'SUBSCRIPTION', 'FIELD', 'FRAGMENT_DEFINITION',
      'FRAGMENT_SPREAD', 'INLINE_FRAGMENT']),

  __Schema: object('__Schema', null, {
    description: { type: 'String' },
    types: {
      type: '[__Type!]!',
      resolve: (_s, _a, ctx) => Object.values(ctx.schema.types),
    },
    queryType: { type: '__Type!', resolve: (_s, _a, ctx) => ctx.schema.types.Query },
    mutationType: { type: '__Type' },
    subscriptionType: { type: '__Type' },
    directives: { type: '[__Directive!]!', resolve: (_s, _a, ctx) => ctx.schema.directives },
  }),

  __Type: object('__Type', null, {
    kind: { type: '__TypeKind!' },
    name: { type: 'String', resolve: (t) => t.name ?? null },
    description: { type: 'String', resolve: (t) => t.description ?? null },
    specifiedByURL: { type: 'String', resolve: () => null },
    fields: {
      type: '[__Field!]',
      args: { includeDeprecated: { type: 'Boolean', defaultValue: false } },
      resolve: (t) => t.kind !== 'OBJECT' ? null
        : Object.entries(t.fields).map(([name, f]) => ({ name, ...f })),
    },
    interfaces: { type: '[__Type!]', resolve: (t) => t.kind === 'OBJECT' ? [] : null },
    possibleTypes: { type: '[__Type!]', resolve: () => null },
    enumValues: {
      type: '[__EnumValue!]',
      args: { includeDeprecated: { type: 'Boolean', defaultValue: false } },
      resolve: (t) => t.kind === 'ENUM' ? t.values : null,
    },
    inputFields: { type: '[__InputValue!]', resolve: () => null },
    ofType: {
      type: '__Type',
      resolve: (t, _a, ctx) => t.ofType ? typeSource(ctx.schema, t.ofType) : null,
    },
  }),

  __Field: object('__Field', null, {
    name: { type: 'String!' },
    description: { type: 'String', resolve: (f) => f.description ?? null },
    args: {
      type: '[__InputValue!]!',
      args: { includeDeprecated: { type: 'Boolean', defaultValue: false } },
      resolve: (f) => Object.entries(f.args ?? {}).map(([name, a]) => ({ name, ...a })),
    },
    type: { type: '__Type!', resolve: (f, _a, ctx) => typeSource(ctx.schema, parseRef(f.type)) },
    isDeprecated: { type: 'Boolean!', resolve: () => false },
    deprecationReason: { type: 'String', resolve: () => null },
  }),

  __InputValue: object('__InputValue', null, {
    name: { type: 'String!' },
    description: { type: 'String', resolve: (a) => a.description ?? null },
    type: { type: '__Type!', resolve: (a, _x, ctx) => typeSource(ctx.schema, parseRef(a.type)) },
    defaultValue: {
      type: 'String',
      resolve: (a) => a.defaultValue === undefined ? null : printValue(a.defaultValue),
    },
    isDeprecated: { type: 'Boolean!', resolve: () => false },
    deprecationReason: { type: 'String', resolve: () => null },
  }),

  __EnumValue: object('__EnumValue', null, {
    name: { type: 'String!' },
    description: { type: 'String', resolve: (v) => v.description ?? null },
    isDeprecated: { type: 'Boolean!', resolve: () => false },
    deprecationReason: { type: 'String', resolve: () => null },
  }),

  __Directive: object('__Directive', null, {
    name: { type: 'String!' },
    description: { type: 'String', resolve: (d) => d.description ?? null },
    locations: { type: '[__DirectiveLocation!]!' },
    args: {
      type: '[__InputValue!]!',
      resolve: (d) => Object.entries(d.args ?? {}).map(([name, a]) => ({ name, ...a })),
    },
    isRepeatable: { type: 'Boolean!', resolve: () => false },
  }),
};

/** The one schema this surface serves. */
export const schema = {
  types: { Query: QUERY, ...DOMAIN, ...SCALARS, ...INTROSPECTION },
  directives: [
    { name: 'skip', args: { if: { type: 'Boolean!' } },
      locations: ['FIELD', 'FRAGMENT_SPREAD', 'INLINE_FRAGMENT'] },
    { name: 'include', args: { if: { type: 'Boolean!' } },
      locations: ['FIELD', 'FRAGMENT_SPREAD', 'INLINE_FRAGMENT'] },
  ],
};

/** Wrap a parsed reference into the source shape `__Type` resolvers expect. */
function typeSource(sch, ref) {
  if (ref.kind === 'NAMED') {
    const t = sch.types[ref.name];
    if (!t) throw new GraphQLError(`unknown type ${ref.name}`);
    return t;
  }
  return { kind: ref.kind, ofType: ref.ofType };
}

function printValue(v) {
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  if (Array.isArray(v)) return '[' + v.map(printValue).join(', ') + ']';
  return '{' + Object.entries(v).map(([k, x]) => `${k}: ${printValue(x)}`).join(', ') + '}';
}

// --------------------------------------------------------------- validation

const fieldOf = (type, name) => type.kind === 'OBJECT' ? type.fields?.[name] : undefined;

/**
 * Validate before executing, so a malformed query fails as one error list
 * instead of a half-filled response. This is a useful subset of the spec's
 * validation rules, not all of them: it catches unknown fields, unknown or
 * missing arguments, leaf/branch selection mistakes, unknown fragments and
 * undeclared variables — the mistakes a hand-written query actually makes.
 */
function validate(sch, doc, op) {
  const errors = [];
  const declared = new Set(op.vars.map((v) => v.name));
  const seen = new Set();

  const checkArgs = (def, sel, where) => {
    const defs = def.args ?? {};
    for (const [name, node] of Object.entries(sel.args ?? {})) {
      if (!(name in defs)) errors.push(`unknown argument "${name}" on ${where}`);
      if (node.kind === 'variable' && !declared.has(node.name)) {
        errors.push(`variable $${node.name} is not declared by this operation`);
      }
    }
    for (const [name, a] of Object.entries(defs)) {
      const required = parseRef(a.type).kind === 'NON_NULL' && a.defaultValue === undefined;
      if (required && !(name in (sel.args ?? {}))) {
        errors.push(`argument "${name}" is required on ${where}`);
      }
    }
  };

  const walk = (type, selections, where) => {
    for (const sel of selections) {
      if (sel.kind === 'spread') {
        const frag = doc.fragments[sel.name];
        if (!frag) { errors.push(`unknown fragment "${sel.name}"`); continue; }
        if (seen.has(sel.name)) continue;  // cycles are not executed
        seen.add(sel.name);
        const target = sch.types[frag.typeCondition];
        if (!target) errors.push(`fragment "${sel.name}" is on unknown type "${frag.typeCondition}"`);
        else walk(target, frag.selections, `fragment ${sel.name}`);
        seen.delete(sel.name);
        continue;
      }
      if (sel.kind === 'inline') {
        const target = sel.typeCondition ? sch.types[sel.typeCondition] : type;
        if (!target) errors.push(`inline fragment on unknown type "${sel.typeCondition}"`);
        else walk(target, sel.selections, where);
        continue;
      }
      if (sel.name === '__typename') continue;
      if (type === sch.types.Query && (sel.name === '__schema' || sel.name === '__type')) {
        const t = sel.name === '__schema' ? sch.types.__Schema : sch.types.__Type;
        if (sel.selections) walk(t, sel.selections, sel.name);
        continue;
      }
      const def = fieldOf(type, sel.name);
      if (!def) {
        errors.push(`cannot query field "${sel.name}" on type "${type.name}"`);
        continue;
      }
      checkArgs(def, sel, `${type.name}.${sel.name}`);
      const named = sch.types[namedOf(parseRef(def.type))];
      if (named.kind === 'OBJECT') {
        if (!sel.selections) errors.push(`field "${sel.name}" of type ${named.name} needs a selection`);
        else walk(named, sel.selections, where);
      } else if (sel.selections) {
        errors.push(`field "${sel.name}" of type ${named.name} cannot have a selection`);
      }
    }
  };

  walk(sch.types.Query, op.selections, 'query');
  return errors;
}

// ---------------------------------------------------------------- execution

class NullBubble extends Error {}

function coerceInput(ref, node, vars, where) {
  if (node.kind === 'variable') {
    const v = vars[node.name];
    return v === undefined ? null : v;
  }
  if (ref.kind === 'NON_NULL') {
    const v = coerceInput(ref.ofType, node, vars, where);
    if (v === null) throw new GraphQLError(`${where} must not be null`);
    return v;
  }
  if (node.kind === 'null') return null;
  if (ref.kind === 'LIST') {
    const items = node.kind === 'list' ? node.value : [node];
    return items.map((n) => coerceInput(ref.ofType, n, vars, where));
  }
  switch (ref.name) {
    case 'Int': {
      if (node.kind !== 'int') throw new GraphQLError(`${where} expects Int`);
      return node.value;
    }
    case 'Float': return Number(node.value);
    case 'Boolean': {
      if (node.kind !== 'boolean') throw new GraphQLError(`${where} expects Boolean`);
      return node.value;
    }
    case 'String': case 'ID': {
      if (node.kind !== 'string' && node.kind !== 'int') {
        throw new GraphQLError(`${where} expects String`);
      }
      return String(node.value);
    }
    default: {
      // Enums arrive as bare names; a quoted string is the usual client slip.
      if (node.kind === 'enum' || node.kind === 'string') return String(node.value);
      throw new GraphQLError(`${where} expects ${ref.name}`);
    }
  }
}

function coerceVariables(op, values) {
  const out = {};
  for (const v of op.vars) {
    const given = values?.[v.name];
    if (given === undefined) {
      out[v.name] = v.defaultValue === undefined ? null : literalOf(v.defaultValue);
      if (v.type.kind === 'NON_NULL' && out[v.name] === null) {
        throw new GraphQLError(`variable $${v.name} is required`);
      }
      continue;
    }
    if (given === null && v.type.kind === 'NON_NULL') {
      throw new GraphQLError(`variable $${v.name} must not be null`);
    }
    out[v.name] = given;
  }
  return out;
}

const literalOf = (node) => node.kind === 'list' ? node.value.map(literalOf)
  : node.kind === 'object' ? Object.fromEntries(Object.entries(node.value).map(([k, v]) => [k, literalOf(v)]))
    : node.value;

/** Flatten fragments and apply @skip/@include. */
function collectFields(sch, type, selections, ctx, into = new Map()) {
  for (const sel of selections) {
    if (!directiveAllows(sel, ctx)) continue;
    if (sel.kind === 'spread') {
      const frag = ctx.fragments[sel.name];
      if (!frag) continue;
      // No interfaces or unions in this schema, so a condition either names
      // this type or does not apply.
      if (frag.typeCondition && frag.typeCondition !== type.name) continue;
      collectFields(sch, type, frag.selections, ctx, into);
      continue;
    }
    if (sel.kind === 'inline') {
      if (sel.typeCondition && sel.typeCondition !== type.name) continue;
      collectFields(sch, type, sel.selections, ctx, into);
      continue;
    }
    const key = sel.alias ?? sel.name;
    const prior = into.get(key);
    if (prior) {
      // Two selections of the same response key merge their sub-selections.
      prior.selections = [...(prior.selections ?? []), ...(sel.selections ?? [])];
      continue;
    }
    into.set(key, { ...sel, responseKey: key });
  }
  return into;
}

function directiveAllows(sel, ctx) {
  for (const d of sel.directives ?? []) {
    const node = d.args?.if;
    if (!node) continue;
    const v = node.kind === 'variable' ? ctx.vars[node.name] : node.value;
    if (d.name === 'skip' && v === true) return false;
    if (d.name === 'include' && v !== true) return false;
  }
  return true;
}

async function executeSelections(sch, type, selections, source, ctx, path) {
  const out = {};
  for (const sel of collectFields(sch, type, selections, ctx).values()) {
    const key = sel.responseKey;
    const here = [...path, key];

    if (sel.name === '__typename') { out[key] = type.name; continue; }

    let def = fieldOf(type, sel.name);
    if (!def && type === sch.types.Query && sel.name === '__schema') {
      def = { type: '__Schema!', resolve: () => ({}) };
    }
    if (!def && type === sch.types.Query && sel.name === '__type') {
      def = {
        type: '__Type',
        args: { name: { type: 'String!' } },
        resolve: (_s, { name }) => sch.types[name] ?? null,
      };
    }
    if (!def) { out[key] = null; continue; }

    const ref = parseRef(def.type);
    try {
      const args = {};
      for (const [name, a] of Object.entries(def.args ?? {})) {
        const node = sel.args?.[name];
        args[name] = node === undefined
          ? (a.defaultValue === undefined ? undefined : a.defaultValue)
          : coerceInput(parseRef(a.type), node, ctx.vars, `${type.name}.${sel.name}(${name}:)`);
      }
      const raw = def.resolve
        ? await def.resolve(source, args, ctx)
        : source?.[sel.name];
      out[key] = await completeValue(sch, ref, raw, sel.selections, ctx, here);
    } catch (err) {
      if (err instanceof NullBubble) {
        if (ref.kind === 'NON_NULL') throw err;
        out[key] = null;
        continue;
      }
      ctx.errors.push(formatError(err, here));
      if (ref.kind === 'NON_NULL') throw new NullBubble();
      out[key] = null;
    }
  }
  return out;
}

async function completeValue(sch, ref, value, selections, ctx, path) {
  if (ref.kind === 'NON_NULL') {
    const v = await completeValue(sch, ref.ofType, value, selections, ctx, path);
    if (v === null) throw new NullBubble();
    return v;
  }
  if (value === null || value === undefined) return null;
  if (ref.kind === 'LIST') {
    const out = [];
    let i = 0;
    for (const item of value) {
      try {
        out.push(await completeValue(sch, ref.ofType, item, selections, ctx, [...path, i]));
      } catch (err) {
        if (err instanceof NullBubble) {
          if (ref.ofType.kind === 'NON_NULL') throw err;
          out.push(null);
        } else {
          ctx.errors.push(formatError(err, [...path, i]));
          if (ref.ofType.kind === 'NON_NULL') throw new NullBubble();
          out.push(null);
        }
      }
      i++;
    }
    return out;
  }
  const type = sch.types[ref.name];
  if (!type) throw new GraphQLError(`unknown type ${ref.name}`);
  if (type.kind === 'SCALAR') return type.serialize(value);
  if (type.kind === 'ENUM') {
    if (!type.values.some((v) => v.name === value)) {
      throw new GraphQLError(`${JSON.stringify(value)} is not a value of enum ${type.name}`);
    }
    return value;
  }
  return executeSelections(sch, type, selections ?? [], value, ctx, path);
}

function formatError(err, path) {
  const out = { message: err.message, path };
  if (err instanceof Fault) out.extensions = { code: err.code, status: err.status };
  else if (err instanceof GraphQLError) out.extensions = { code: err.code };
  else out.extensions = { code: 'internal' };
  return out;
}

/**
 * Execute one request against the vault surface.
 *
 * Returns `{data, errors?}`. A denial is an error entry with
 * `extensions.code`, never a thrown response: a query that asks for twenty
 * nodes and may read nineteen gets nineteen.
 */
export async function graphql({ source, variables, operationName, surface, principal }) {
  let doc;
  try {
    doc = parse(source);
  } catch (err) {
    return { errors: [{ message: err.message, extensions: { code: 'bad_request' } }] };
  }

  const op = operationName
    ? doc.operations.find((o) => o.name === operationName)
    : doc.operations.length === 1 ? doc.operations[0] : null;
  if (!op) {
    return {
      errors: [{
        message: operationName
          ? `no operation named "${operationName}"`
          : 'the document holds several operations; name one with operationName',
        extensions: { code: 'bad_request' },
      }],
    };
  }
  if (op.type !== 'query') {
    return {
      errors: [{
        message: `${op.type} is not supported: the gatekeeper is a read surface (§12)`,
        extensions: { code: 'method_not_allowed' },
      }],
    };
  }

  const problems = validate(schema, doc, op);
  if (problems.length) {
    return { errors: problems.map((m) => ({ message: m, extensions: { code: 'bad_request' } })) };
  }

  let vars;
  try {
    vars = coerceVariables(op, variables);
  } catch (err) {
    return { errors: [{ message: err.message, extensions: { code: 'bad_request' } }] };
  }

  const ctx = {
    surface, principal, schema, fragments: doc.fragments, vars, errors: [],
  };
  let data = null;
  try {
    data = await executeSelections(schema, schema.types.Query, op.selections, {}, ctx, []);
  } catch (err) {
    if (!(err instanceof NullBubble)) ctx.errors.push(formatError(err, []));
  }
  return ctx.errors.length ? { data, errors: ctx.errors } : { data };
}

// ------------------------------------------------------------- SDL printing

const BLOCK = (text, indent = '') => {
  if (!text) return '';
  const body = text.includes('\n')
    ? `${indent}"""\n${text.split('\n').map((l) => indent + l).join('\n')}\n${indent}"""\n`
    : `${indent}"""${text}"""\n`;
  return body;
};

/** Print the schema as SDL — the artifact other implementations serve. */
export function printSchema(sch = schema) {
  const out = [
    '# The Basalt GraphQL surface (INTEROP §3).',
    '#',
    '# Generated from the type table in ts/src/serve/graphql.mjs by',
    '# `basalt schema graphql`; the server serves this at /graphql/schema.graphql.',
    '# Read-only by construction: there is no Mutation type, because §12 defines',
    '# a read surface and a write surface would need §11 history semantics first.',
    '',
    'schema {',
    '  query: Query',
    '}',
    '',
  ];
  const names = Object.keys(sch.types)
    .filter((n) => !n.startsWith('__') && !(n in SCALARS))
    .sort((a, b) => a === 'Query' ? -1 : b === 'Query' ? 1 : a < b ? -1 : 1);

  for (const name of names) {
    const t = sch.types[name];
    out.push(BLOCK(t.description).trimEnd());
    if (t.kind === 'ENUM') {
      out.push(`enum ${t.name} {`);
      for (const v of t.values) out.push(`  ${v.name}`);
      out.push('}', '');
      continue;
    }
    out.push(`type ${t.name} {`);
    for (const [fname, f] of Object.entries(t.fields)) {
      if (f.description) out.push(BLOCK(f.description, '  ').trimEnd());
      const args = Object.entries(f.args ?? {});
      const arglist = args.length
        ? '(' + args.map(([an, a]) => `${an}: ${a.type}`
          + (a.defaultValue === undefined ? '' : ` = ${printValue(a.defaultValue)}`)).join(', ') + ')'
        : '';
      out.push(`  ${fname}${arglist}: ${f.type}`);
    }
    out.push('}', '');
  }
  return out.filter((l) => l !== undefined).join('\n').replace(/\n{3,}/g, '\n\n');
}
