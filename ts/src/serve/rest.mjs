// The REST surface, PROTOCOL §12.3 and INTEROP §2.
//
// The route table below is the single source of truth: the dispatcher and the
// OpenAPI 3.1 document are both generated from it, so a route cannot exist
// without being described, and a description cannot drift from the route it
// documents. `basalt schema openapi` emits the same document the server
// serves at /api/v1/openapi.json.

import { canonicalJson } from '../canonical.mjs';
import { Fault, mediaFor } from './core.mjs';

const API = '/api/v1';

/** Compile `/api/v1/node/{path}` into a matcher. `{path}` may contain slashes. */
function compile(template) {
  const names = [];
  const pattern = template.replace(/\{(\w+)\}|[.*+?^${}()|[\]\\]/g, (m, name) => {
    if (!name) return '\\' + m;
    names.push(name);
    return name === 'path' || name === 'folder' ? '(.*)' : '([^/]+)';
  });
  return { regex: new RegExp(`^${pattern}$`), names };
}

/**
 * Every REST route, with the OpenAPI metadata that describes it.
 *
 * `handler` receives the surface, the principal and the parsed request; it
 * returns `{body}` for canonical JSON, or `{bytes, mediaType}` /
 * `{redirect}` for the byte routes.
 */
export const ROUTES = [
  {
    template: `${API}/manifest`,
    operationId: 'getManifest',
    summary: 'The public subset of the manifest (§3.1).',
    schema: 'Manifest',
    handler: (s, p) => ({ body: s.manifest() }),
  },
  {
    template: `${API}/me`,
    operationId: 'getMe',
    summary: 'The principal this request reduced to, and its subject set (§8.4).',
    schema: 'Identity',
    handler: (s, p) => ({ body: s.me(p) }),
  },
  {
    template: `${API}/openapi.json`,
    operationId: 'getOpenapi',
    summary: 'This document.',
    schema: 'Any',
    handler: (s, p, { baseUrl }) => ({ body: openapiDocument(s, { baseUrl }) }),
  },
  {
    template: `${API}/node/{path}`,
    operationId: 'getNode',
    summary: 'Content plus metadata and edges, if `read` (§12.3).',
    params: [{ name: 'path', in: 'path', required: true, description: 'Vault path.' }],
    schema: 'NodeResponse',
    handler: async (s, p, { params }) => ({ body: shapeNode(await s.node(p, params.path)) }),
  },
  {
    template: `${API}/raw/{path}`,
    operationId: 'getRaw',
    summary: 'The bytes of a node, if `read`. May 302 to a presigned URL (§12.4).',
    params: [{ name: 'path', in: 'path', required: true, description: 'Vault path.' }],
    schema: 'Bytes',
    handler: async (s, p, { params }) => {
      const r = await s.raw(p, params.path);
      if (r.redirect) return { redirect: r.redirect };
      return { bytes: r.bytes, mediaType: r.media_type, etag: r.etag };
    },
  },
  {
    template: `${API}/list/{folder}`,
    operationId: 'listFolder',
    summary: 'Direct entries of a folder, filtered to those with `list` (§12.3).',
    params: [{ name: 'folder', in: 'path', required: true, description: 'Folder path, or empty for the root.' }],
    schema: 'FolderListing',
    handler: (s, p, { params }) => ({ body: s.list(p, params.folder) }),
  },
  {
    template: `${API}/list`,
    operationId: 'listRoot',
    summary: 'Direct entries of the vault root.',
    schema: 'FolderListing',
    handler: (s, p) => ({ body: s.list(p, '') }),
  },
  {
    template: `${API}/nodes`,
    operationId: 'listNodes',
    summary: 'Every readable node entry, in §13.3 order.',
    params: [
      { name: 'limit', in: 'query', schema: { type: 'integer', default: 100, maximum: 1000 } },
      { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
      { name: 'published', in: 'query', schema: { type: 'boolean', default: false },
        description: 'Exclude nodes whose frontmatter sets `publish: false`.' },
    ],
    schema: 'NodeCatalogue',
    handler: (s, p, { query }) => {
      const all = s.nodes(p, { publishedOnly: query.get('published') === 'true' });
      const limit = Math.min(1000, Math.max(1, Number(query.get('limit') ?? 100) || 100));
      const offset = Math.max(0, Number(query.get('offset') ?? 0) || 0);
      return {
        body: {
          total: all.length, offset, limit,
          entries: all.slice(offset, offset + limit),
        },
      };
    },
  },
  {
    template: `${API}/links/{path}`,
    operationId: 'getLinks',
    summary: 'Out-edges and backlinks, redacted in place per §9.5.',
    params: [{ name: 'path', in: 'path', required: true }],
    schema: 'LinkSet',
    handler: (s, p, { params }) => ({ body: s.links(p, params.path) }),
  },
  {
    template: `${API}/search`,
    operationId: 'search',
    summary: 'Postings filtered to readable nodes, not merely re-ranked (§12.5).',
    params: [
      { name: 'q', in: 'query', required: true, schema: { type: 'string' } },
      { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 200 } },
      { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
    ],
    schema: 'SearchResult',
    handler: (s, p, { query }) => ({
      body: s.search(p, query.get('q') ?? '', {
        limit: query.get('limit') ?? 20, offset: query.get('offset') ?? 0,
      }),
    }),
  },
  {
    template: `${API}/tree`,
    operationId: 'getTree',
    summary: 'The navigable tree, pruned to what is visible (§12.3).',
    schema: 'TreeResponse',
    handler: (s, p) => ({ body: { tree: s.tree(p) } }),
  },
  {
    template: `${API}/tags`,
    operationId: 'getTags',
    summary: 'Tag postings, filtered to readable nodes (§9.6).',
    schema: 'TagListing',
    handler: (s, p) => ({ body: { tags: s.tags(p) } }),
  },
  {
    template: `${API}/effective`,
    operationId: 'getEffective',
    summary: 'Effective rights with the deciding ACE per right; needs `read_acl` (§8.7).',
    params: [
      { name: 'path', in: 'query', required: true, schema: { type: 'string' } },
      { name: 'principal', in: 'query', schema: { type: 'string' },
        description: 'Defaults to the requesting principal.' },
    ],
    schema: 'Effective',
    handler: (s, p, { query }) => ({
      body: s.effective(p, {
        path: query.get('path') ?? '',
        principal: query.get('principal') ?? undefined,
      }),
    }),
  },
].map((r) => ({ ...r, ...compile(r.template) }));

/** Flatten a Surface node result into the REST body shape. */
function shapeNode(r) {
  return { node: r.node, text: r.text, media_type: r.media_type, links: r.links };
}

/**
 * Dispatch a REST request. Returns false when no route matched, so the router
 * can try the next surface.
 */
export async function handleRest(surface, principal, req, res, { baseUrl, send } = {}) {
  const url = new URL(req.url, baseUrl ?? 'http://localhost');
  for (const route of ROUTES) {
    const m = url.pathname.match(route.regex);
    if (!m) continue;

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      send(res, 405, problem('method_not_allowed', `${req.method} is not allowed`), {
        'content-type': 'application/problem+json', allow: 'GET, HEAD',
      });
      return true;
    }

    let params;
    try {
      params = Object.fromEntries(route.names.map((n, i) => [n, decodeURIComponent(m[i + 1])]));
    } catch {
      send(res, 400, problem('bad_request', 'malformed percent-encoding in the path'),
        { 'content-type': 'application/problem+json' });
      return true;
    }

    try {
      const out = await route.handler(surface, principal, {
        params, query: url.searchParams, baseUrl, req,
      });

      if (out.redirect) {
        // §12.4: a presigned URL is a bearer token that outlives the ACL check
        // that produced it, so it never enters a shared cache.
        send(res, 302, '', { location: out.redirect, 'cache-control': 'private, no-store' });
        return true;
      }

      const bytes = out.bytes ?? Buffer.from(canonicalJson(out.body), 'utf8');
      const etag = out.etag ?? surface.etag(bytes);
      const type = out.mediaType ?? 'application/json';

      // Conditional GET. The etag of a derived response depends on the
      // principal's visibility, so the response stays `private` — a shared
      // cache keyed on the URL alone would serve one subject set's etag to
      // another (§12.5).
      const inm = req.headers['if-none-match'];
      if (inm && inm.split(',').some((t) => t.trim() === etag)) {
        send(res, 304, '', { etag, 'content-type': type });
        return true;
      }
      send(res, 200, bytes, { etag, 'content-type': type });
      return true;
    } catch (err) {
      const f = err instanceof Fault ? err : new Fault('internal', err.message);
      send(res, f.status, problem(f.code, f.detail), {
        'content-type': 'application/problem+json',
      });
      return true;
    }
  }
  return false;
}

/**
 * RFC 9457 problem details, carrying the legacy `error` member as well so a
 * client written against the pre-INTEROP gatekeeper keeps working.
 */
export function problem(code, detail) {
  const titles = {
    not_found: 'Not found',
    forbidden: 'Forbidden',
    unauthenticated: 'Authentication required',
    bad_request: 'Bad request',
    method_not_allowed: 'Method not allowed',
    unsupported_media: 'Unsupported media type',
    internal: 'Internal error',
  };
  const body = {
    type: `urn:basalt:problem:${code}`,
    title: titles[code] ?? 'Error',
    error: code,
  };
  if (detail) body.detail = detail;
  return body;
}

// ------------------------------------------------------------------ OpenAPI

const NODE_ENTRY = {
  type: 'object',
  description: 'A node entry as it appears in index/nodes.json (§10.1).',
  required: ['path', 'id', 'kind', 'title', 'content_hash'],
  properties: {
    path: { type: 'string', description: 'Vault path (§2.1).' },
    id: { type: 'string', description: 'ULID node id (§4.1).' },
    kind: { type: 'string', enum: ['note', 'data', 'asset'] },
    title: { type: 'string' },
    size: { type: 'integer' },
    content_hash: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' },
    etag: { type: 'string', description: 'Store etag; excluded from conformance comparison (§13.2).' },
    publish: { type: 'boolean' },
    tags: { type: 'array', items: { type: 'string' } },
    aliases: { type: 'array', items: { type: 'string' } },
    headings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          level: { type: 'integer' }, slug: { type: 'string' }, text: { type: 'string' },
        },
      },
    },
    errors: { type: 'array', items: { type: 'string' } },
  },
};

const LINK_EDGE = {
  type: 'object',
  description: 'A resolved edge from index/links.json (§10.2). `to: "redacted"` is §9.5.',
  properties: {
    from: { type: 'string' },
    to: { type: ['string', 'null'] },
    kind: { type: 'string', enum: ['wiki', 'markdown', 'embed', 'tag'] },
    raw: { type: 'string' },
    alias: { type: ['string', 'null'] },
    anchor: { type: ['string', 'null'] },
    anchor_resolved: { type: 'boolean' },
    ambiguous: { type: 'boolean' },
    candidates: { type: 'array', items: { type: 'string' } },
    line: { type: 'integer' }, col: { type: 'integer' },
    target: {
      type: ['object', 'null'],
      properties: {
        id: { type: 'string' },
        path: { type: ['string', 'null'] },
        title: { type: ['string', 'null'] },
      },
    },
  },
};

const RIGHT = {
  type: 'string',
  enum: ['read', 'list', 'traverse', 'comment', 'write', 'create_child', 'delete',
    'delete_child', 'read_acl', 'write_acl', 'take_ownership', 'read_history', 'publish'],
};

const SCHEMAS = {
  Any: {},
  Bytes: { type: 'string', format: 'binary' },
  NodeEntry: NODE_ENTRY,
  LinkEdge: LINK_EDGE,
  Right: RIGHT,
  Manifest: {
    type: 'object',
    properties: {
      basalt: { type: 'integer', const: 1 },
      vault: {
        type: 'object',
        properties: { id: { type: 'string' }, title: { type: ['string', 'null'] } },
      },
      publish: {
        type: 'object',
        properties: {
          audience: { type: 'string', enum: ['public', 'gated', 'private'] },
          home: { type: ['string', 'null'] },
        },
      },
      index_state: { type: 'string', enum: ['fresh', 'stale', 'rebuilt'] },
    },
  },
  Identity: {
    type: 'object',
    properties: {
      principal: { type: 'string' },
      display_name: { type: ['string', 'null'] },
      subjects: { type: 'array', items: { type: 'string' },
        description: 'The effective subject set used by §8.4 step 1.' },
      anonymous: { type: 'boolean' },
    },
  },
  NodeResponse: {
    type: 'object',
    properties: {
      node: { $ref: '#/components/schemas/NodeEntry' },
      text: { type: ['string', 'null'], description: 'Null for binary kinds.' },
      media_type: { type: 'string' },
      links: { $ref: '#/components/schemas/LinkSet' },
    },
  },
  NodeCatalogue: {
    type: 'object',
    properties: {
      total: { type: 'integer' }, offset: { type: 'integer' }, limit: { type: 'integer' },
      entries: { type: 'array', items: { $ref: '#/components/schemas/NodeEntry' } },
    },
  },
  FolderListing: {
    type: 'object',
    properties: {
      folder: { type: 'string' },
      entries: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            path: { type: 'string' }, kind: { type: 'string' },
            title: { type: 'string' }, id: { type: 'string' },
          },
        },
      },
      folders: { type: 'array', items: { type: 'string' } },
    },
  },
  LinkSet: {
    type: 'object',
    properties: {
      path: { type: 'string' },
      out: { type: 'array', items: { $ref: '#/components/schemas/LinkEdge' } },
      backlinks: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' }, path: { type: ['string', 'null'] },
            title: { type: ['string', 'null'] },
          },
        },
      },
    },
  },
  SearchResult: {
    type: 'object',
    properties: {
      query: { type: 'string' }, total: { type: 'integer' }, offset: { type: 'integer' },
      hits: {
        type: 'array',
        items: {
          allOf: [
            { $ref: '#/components/schemas/NodeEntry' },
            { type: 'object', properties: { score: { type: 'integer' } } },
          ],
        },
      },
    },
  },
  TreeResponse: {
    type: 'object',
    properties: { tree: { $ref: '#/components/schemas/TreeNode' } },
  },
  TreeNode: {
    type: ['object', 'null'],
    properties: {
      folder: { type: 'string' }, title: { type: 'string' },
      entries: { type: 'array', items: { type: 'object' } },
      folders: { type: 'array', items: { $ref: '#/components/schemas/TreeNode' } },
    },
  },
  TagListing: {
    type: 'object',
    properties: {
      tags: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            tag: { type: 'string' },
            nodes: { type: 'array', items: { type: 'object' } },
          },
        },
      },
    },
  },
  Effective: {
    type: 'object',
    properties: {
      principal: { type: 'string' }, path: { type: 'string' },
      granted: { type: 'array', items: { $ref: '#/components/schemas/Right' } },
      decisions: {
        type: 'object',
        additionalProperties: {
          type: 'object',
          properties: {
            decision: { type: 'string', enum: ['allow', 'deny'] },
            by: { type: 'string', description: 'The deciding ACE (§8.7).' },
            failed_at: { type: ['string', 'null'] },
          },
        },
      },
      failed_at: { type: ['string', 'null'],
        description: 'The ancestor whose traverse check failed (§8.5).' },
    },
  },
  Problem: {
    type: 'object',
    description: 'RFC 9457 problem details. `error` repeats the code for older clients.',
    properties: {
      type: { type: 'string' }, title: { type: 'string' },
      detail: { type: 'string' }, error: { type: 'string' },
    },
  },
};

/** The OpenAPI 3.1 document for the REST surface, generated from ROUTES. */
export function openapiDocument(surface, { baseUrl } = {}) {
  const paths = {};
  for (const r of ROUTES) {
    const params = (r.params ?? []).map((p) => ({
      name: p.name, in: p.in, required: p.required ?? false,
      description: p.description, schema: p.schema ?? { type: 'string' },
    }));
    const ok = r.schema === 'Bytes'
      ? { '*/*': { schema: { $ref: '#/components/schemas/Bytes' } } }
      : { 'application/json': { schema: { $ref: `#/components/schemas/${r.schema}` } } };

    paths[r.template] = {
      get: {
        operationId: r.operationId,
        summary: r.summary,
        parameters: params.length ? params : undefined,
        responses: {
          200: { description: 'OK', content: ok,
            headers: {
              ETag: { schema: { type: 'string' } },
              'X-Basalt-Vault': { schema: { type: 'string' } },
              'X-Basalt-Index-State': { schema: { type: 'string', enum: ['fresh', 'stale', 'rebuilt'] } },
            } },
          304: { description: 'Not modified.' },
          403: { description: 'The principal may know the object exists but lacks `read` (§12.3).',
            content: { 'application/problem+json': { schema: { $ref: '#/components/schemas/Problem' } } } },
          404: { description: 'No such object, or the principal may not discover it (§12.3).',
            content: { 'application/problem+json': { schema: { $ref: '#/components/schemas/Problem' } } } },
        },
      },
    };
    if (r.schema === 'Bytes') {
      paths[r.template].get.responses[302] = {
        description: 'Presigned redirect, in `redirect` delivery mode (§12.4).',
        headers: { Location: { schema: { type: 'string', format: 'uri' } } },
      };
    }
  }

  return {
    openapi: '3.1.0',
    info: {
      title: `Basalt gatekeeper — ${surface.vaultId}`,
      version: '1.0.0',
      summary: 'Read surface for a Basalt vault, enforcing §8 on every response.',
      description:
        'Every response is evaluated for the requesting principal (§8.4). A 404 '
        + 'means either "no such object" or "you may not discover it" and the two '
        + 'are deliberately indistinguishable (§12.3). Derived responses are '
        + 'private: their etag depends on the requester\'s subject set (§12.5).',
      license: { name: 'MIT', identifier: 'MIT' },
    },
    servers: [{ url: baseUrl ?? '/' }],
    paths,
    components: {
      schemas: SCHEMAS,
      securitySchemes: {
        // §12.1 puts authentication out of scope: the gatekeeper must reduce a
        // request to exactly one principal and must never let a client assert
        // its own id. These are the shapes deployments actually use.
        bearer: { type: 'http', scheme: 'bearer' },
        cookie: { type: 'apiKey', in: 'cookie', name: 'session' },
      },
    },
  };
}
