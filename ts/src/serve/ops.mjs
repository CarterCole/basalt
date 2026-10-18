// The operation table, INTEROP §1.2.
//
// REST has a route per operation and the method-call surfaces (JSON-RPC, MCP
// tools, Connect/gRPC) have one entry each. They are the same operations, so
// they are declared once here with a JSON Schema for the arguments, and each
// adapter projects this table into its own naming convention. A new operation
// appears in every method-call surface at once, which is the only way to keep
// five protocols honestly equivalent.

import { Fault } from './core.mjs';

const S = (description, extra = {}) => ({ type: 'string', description, ...extra });
const I = (description, def) => ({ type: 'integer', description, default: def });
const B = (description, def) => ({ type: 'boolean', description, default: def });

const schema = (properties, required = []) => ({
  type: 'object', properties, required, additionalProperties: false,
});

const num = (v, fallback) => {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
};
const bool = (v, fallback = false) =>
  v === undefined || v === null ? fallback : v === true || v === 'true';

const need = (args, name) => {
  const v = args?.[name];
  if (typeof v !== 'string' || v === '') throw new Fault('bad_request', `${name} is required`);
  return v;
};

/**
 * Every read operation the vault exposes.
 *
 * `rpc` is the JSON-RPC method name, `tool` the MCP tool name, `proto` the
 * Connect/gRPC method. One operation, three spellings, no behaviour of its
 * own anywhere: `call` goes straight to the surface, which is what enforces
 * §8 (INTEROP §1.1).
 */
export const OPERATIONS = [
  {
    name: 'manifest', proto: 'GetManifest',
    summary: 'The vault manifest: id, title, audience, index freshness (§3.1).',
    input: schema({}),
    call: (s, p) => s.manifest(),
  },
  {
    name: 'me', proto: 'GetIdentity',
    summary: 'The principal this request reduced to, and its subject set (§8.4).',
    input: schema({}),
    call: (s, p) => s.me(p),
  },
  {
    name: 'node', proto: 'GetNode',
    summary: 'Read one node: metadata, text and edges, if the principal holds `read`.',
    input: schema({
      path: S('Vault path, e.g. "Notes/Columns.md".'),
      include_text: B('Include the UTF-8 text. Default true.', true),
      include_bytes: B('Include the raw bytes, base64-encoded. Default false.', false),
    }, ['path']),
    call: async (s, p, a) => {
      const r = await s.node(p, need(a, 'path'));
      const out = { node: r.node, media_type: r.media_type, links: r.links };
      if (bool(a.include_text, true)) out.text = r.text;
      if (bool(a.include_bytes, false)) {
        out.base64 = r.bytes ? Buffer.from(r.bytes).toString('base64') : null;
      }
      return out;
    },
  },
  {
    name: 'list', proto: 'ListFolder',
    summary: 'Direct entries of a folder, filtered to those the principal may see.',
    input: schema({ folder: S('Folder path with a trailing slash, or "" for the root.') }),
    call: (s, p, a) => s.list(p, a.folder ?? ''),
  },
  {
    name: 'nodes', proto: 'ListNodes',
    summary: 'Every readable node entry, in §13.3 order.',
    input: schema({
      limit: I('Maximum entries. Default 100, cap 1000.', 100),
      offset: I('Entries to skip.', 0),
      published: B('Exclude nodes whose frontmatter sets publish: false.', false),
    }),
    call: (s, p, a) => {
      const all = s.nodes(p, { publishedOnly: bool(a.published) });
      const limit = Math.min(1000, Math.max(1, num(a.limit, 100)));
      const offset = Math.max(0, num(a.offset, 0));
      return { total: all.length, offset, limit, entries: all.slice(offset, offset + limit) };
    },
  },
  {
    name: 'links', proto: 'GetLinks',
    summary: 'Out-edges and backlinks for a node. Invisible targets are redacted (§9.5).',
    input: schema({ path: S('Vault path.') }, ['path']),
    call: (s, p, a) => s.links(p, need(a, 'path')),
  },
  {
    name: 'search', proto: 'Search',
    summary: 'Full-text search over readable nodes only (§12.5).',
    input: schema({
      q: S('Query terms.'),
      limit: I('Maximum hits. Default 20, cap 200.', 20),
      offset: I('Hits to skip.', 0),
    }, ['q']),
    call: (s, p, a) => s.search(p, need(a, 'q'), { limit: num(a.limit, 20), offset: num(a.offset, 0) }),
  },
  {
    name: 'tree', proto: 'GetTree',
    summary: 'The navigable folder tree, pruned to what the principal may see.',
    input: schema({}),
    call: (s, p) => ({ tree: s.tree(p) }),
  },
  {
    name: 'tags', proto: 'GetTags',
    summary: 'Tags and the readable nodes carrying them (§9.6).',
    input: schema({}),
    call: (s, p) => ({ tags: s.tags(p) }),
  },
  {
    name: 'recent', proto: 'GetRecent',
    summary: 'Readable nodes by store mtime, newest first.',
    input: schema({
      limit: I('Maximum entries. Default 20, cap 500.', 20),
      published: B('Exclude nodes whose frontmatter sets publish: false. Default true.', true),
    }),
    call: async (s, p, a) => ({
      entries: await s.recent(p, { limit: num(a.limit, 20), publishedOnly: bool(a.published, true) }),
    }),
  },
  {
    name: 'effective', proto: 'GetEffectiveRights',
    summary: 'Effective rights and the deciding ACE per right. Needs `read_acl` (§8.7).',
    input: schema({
      path: S('Vault path, or "" for the root folder.'),
      principal: S('Principal to evaluate. Defaults to the caller.'),
    }, ['path']),
    call: (s, p, a) => s.effective(p, {
      path: a.path ?? '', principal: a.principal || undefined,
    }),
  },
];

export const OP_BY_NAME = new Map(OPERATIONS.map((o) => [o.name, o]));
export const OP_BY_PROTO = new Map(OPERATIONS.map((o) => [o.proto, o]));
