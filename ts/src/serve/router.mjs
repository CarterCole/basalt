// The router, INTEROP §1.4.
//
// One HTTP listener, one identity step, one surface object, many protocols.
// The identity step happens here and exactly once (§12.1): no adapter may
// read a principal off the request, so no adapter can be talked into
// accepting a client-asserted one.

import { canonicalJson } from '../canonical.mjs';
import { Surface } from './core.mjs';
import { handleRest, problem } from './rest.mjs';
import { graphql, printSchema } from './graphql.mjs';
import { handleText } from './jsonrpc.mjs';
import { rpcMethods } from './rpc.mjs';
import { mcpMethods, MCP_VERSIONS, MCP_LATEST } from './mcp.mjs';
import { handleConnect, connectDescriptor, SERVICE } from './connect.mjs';
import { handleWebdav } from './webdav.mjs';
import { atom, rss, sitemap, opensearch, robots } from './feeds.mjs';
import { jsonld, turtle, RDF_NS } from './rdf.mjs';
import { OPERATIONS } from './ops.mjs';

const MAX_BODY = 1 << 20;  // 1 MiB: every request here is a query, not an upload.

/** Read a request body, refusing one that is implausible for a query. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('request body too large'), { tooLarge: true }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const wantsHtml = (req) => (req.headers.accept ?? '').includes('text/html');

export class Router {
  /**
   * @param {import('../vault.mjs').Vault} vault
   * @param {object} [opts]
   * @param {(req) => string} [opts.identify] §12.1: reduce a request to one
   *   principal id. The default is `anonymous` for everything.
   * @param {'proxy'|'redirect'} [opts.delivery]
   * @param {string} [opts.publicUrl] absolute base for feeds, sitemaps and RDF
   *   IRIs; derived from the request when absent.
   * @param {string|null} [opts.cors] an Access-Control-Allow-Origin value.
   *   Off by default: these responses are per-principal, and a wildcard with
   *   credentials is how a cross-origin page reads someone else's vault.
   * @param {Set<string>} [opts.surfaces] which surfaces to mount. Omitted,
   *   the manifest's `publish.interop` bounds the set (§3.1, INTEROP §10);
   *   a manifest that says nothing gets DEFAULT_SURFACES — the §12 REST API
   *   alone. Interop profiles are opt-in, never inherited from silence.
   * @param {import('../web/site.mjs').Site|null} [opts.site] the HTML publish
   *   site (§12.6), which takes every path the protocol surfaces do not claim.
   */
  constructor(vault, {
    identify, delivery = 'proxy', publicUrl, cors = null, surfaces,
    serverVersion = '1.0.0', site = null,
  } = {}) {
    this.vault = vault;
    this.site = site;
    this.identify = identify ?? (() => 'anonymous');
    this.publicUrl = publicUrl ?? null;
    this.cors = cors;
    this.serverVersion = serverVersion;
    this.enabled = surfaces ?? declaredSurfaces(vault);
    this.surface = new Surface(vault, { delivery });
  }

  get indexState() { return this.surface.state; }
  set indexState(v) { this.surface.state = v; }

  invalidate() { this.surface.invalidate(); }

  /** The absolute base URL for this request, honouring a reverse proxy. */
  #base(req) {
    if (this.publicUrl) return this.publicUrl.replace(/\/$/, '');
    const proto = (req.headers['x-forwarded-proto'] ?? 'http').split(',')[0].trim();
    const host = (req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost').split(',')[0].trim();
    return `${proto}://${host}`;
  }

  #send(req, surfaceName) {
    return (res, status, body, headers = {}) => {
      const payload = body === undefined || body === null ? ''
        : Buffer.isBuffer(body) || typeof body === 'string' ? body
          : canonicalJson(body);
      const out = {
        'content-type': 'application/json',
        'x-basalt-vault': this.surface.vaultId,
        'x-basalt-index-state': this.surface.state,
        'x-basalt-surface': surfaceName,
        // Every body here depends on the principal, so a shared cache keyed on
        // the URL alone would serve one subject set's view to another (§12.5).
        'cache-control': 'private, no-store',
        vary: 'accept, authorization, cookie',
        // Content is author-supplied on several of these surfaces; never let a
        // browser sniff a note into something executable.
        'x-content-type-options': 'nosniff',
        ...(this.cors ? {
          'access-control-allow-origin': this.cors,
          'access-control-allow-headers': 'content-type, authorization, mcp-protocol-version, depth',
          'access-control-allow-methods': 'GET, HEAD, POST, OPTIONS, PROPFIND',
          'access-control-expose-headers': 'etag, x-basalt-vault, x-basalt-index-state, x-basalt-surface',
        } : {}),
        ...headers,
      };
      for (const [k, v] of Object.entries(out)) if (v === undefined) delete out[k];
      res.writeHead(status, out);
      // A HEAD response carries the headers of the GET and none of the body.
      res.end(req.method === 'HEAD' ? undefined : payload);
    };
  }

  async handle(req, res) {
    const base = this.#base(req);
    const url = new URL(req.url, base);
    const principal = this.identify(req);
    const path = url.pathname;
    let send = this.#send(req, 'router');

    try {
      if (req.method === 'OPTIONS' && this.cors && !path.startsWith('/dav')) {
        send(res, 204, '', { 'content-length': '0' });
        return;
      }

      let body = Buffer.alloc(0);
      if (req.method === 'POST' || req.method === 'PROPFIND' || req.method === 'PUT') {
        try {
          body = await readBody(req);
        } catch (err) {
          send(res, err.tooLarge ? 413 : 400, problem('bad_request', err.message),
            { 'content-type': 'application/problem+json' });
          return;
        }
      }

      // ------------------------------------------------- discovery (§1.4)
      if (path === '/.well-known/basalt' || path === '/.well-known/basalt.json') {
        send = this.#send(req, 'discovery');
        send(res, 200, this.discovery(base), {
          'content-type': 'application/json',
          // The one response that is identical for everyone: it describes the
          // surfaces, never the content.
          'cache-control': 'public, max-age=60',
        });
        return;
      }
      if (path === '/' && !(this.site && wantsHtml(req))) {
        send = this.#send(req, 'discovery');
        if (wantsHtml(req)) {
          send(res, 200, this.landing(base), { 'content-type': 'text/html; charset=utf-8' });
        } else {
          send(res, 200, this.discovery(base));
        }
        return;
      }

      // ------------------------------------------------------- REST (§2)
      if (this.enabled.has('rest') && path.startsWith('/api/v1')) {
        send = this.#send(req, 'rest');
        if (await handleRest(this.surface, principal, req, res, { baseUrl: base, send })) return;
      }

      // ---------------------------------------------------- GraphQL (§3)
      if (this.enabled.has('graphql') && (path === '/graphql' || path === '/graphql/schema.graphql')) {
        send = this.#send(req, 'graphql');
        return await this.#graphql(req, res, { url, principal, body, send });
      }

      // ------------------------------------------- JSON-RPC and MCP (§4)
      if (this.enabled.has('jsonrpc') && path === '/rpc') {
        send = this.#send(req, 'jsonrpc');
        if (req.method !== 'POST') {
          send(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'POST a JSON-RPC request' } },
            { allow: 'POST' });
          return;
        }
        const out = await handleText(rpcMethods(this.surface, principal), body.toString('utf8'));
        send(res, 200, out ?? '', { 'content-type': 'application/json' });
        return;
      }

      if (this.enabled.has('mcp') && path === '/mcp') {
        send = this.#send(req, 'mcp');
        if (req.method !== 'POST') {
          // No SSE stream: this server has no server-initiated messages to
          // send, so the GET half of Streamable HTTP would stay silent.
          send(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'POST a JSON-RPC request; this server opens no SSE stream' } },
            { allow: 'POST' });
          return;
        }
        const methods = mcpMethods(this.surface, principal, { serverVersion: this.serverVersion });
        const out = await handleText(methods, body.toString('utf8'));
        const asked = req.headers['mcp-protocol-version'];
        send(res, 200, out ?? '', {
          'content-type': 'application/json',
          'mcp-protocol-version': MCP_VERSIONS.includes(asked) ? asked : MCP_LATEST,
        });
        return;
      }

      // ---------------------------------------------- Connect/gRPC (§5)
      if (this.enabled.has('connect') && path.startsWith(`/${SERVICE}/`)) {
        send = this.#send(req, 'connect');
        if (await handleConnect(this.surface, principal, req, res, { body, send, baseUrl: base })) return;
      }

      // --------------------------------------------------- WebDAV (§6)
      if (this.enabled.has('webdav') && (path === '/dav' || path.startsWith('/dav/'))) {
        send = this.#send(req, 'webdav');
        if (await handleWebdav(this.surface, principal, req, res, { body, send, baseUrl: base })) return;
      }

      // ---------------------------------------------------- feeds (§7)
      if (this.enabled.has('feeds') && FEEDS[path]) {
        send = this.#send(req, 'feeds');
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          send(res, 405, problem('method_not_allowed'), { allow: 'GET, HEAD' });
          return;
        }
        const { type, body: make } = FEEDS[path];
        const text = await make(this.surface, principal, { base, now: new Date().toISOString() });
        send(res, 200, text, { 'content-type': type });
        return;
      }

      // ------------------------------------------------------ RDF (§8)
      if (this.enabled.has('rdf') && (path === '/graph.jsonld' || path === '/graph.ttl')) {
        send = this.#send(req, 'rdf');
        if (path === '/graph.ttl') {
          send(res, 200, turtle(this.surface, principal, { base }),
            { 'content-type': 'text/turtle; charset=utf-8' });
        } else {
          send(res, 200, jsonld(this.surface, principal, { base }),
            { 'content-type': 'application/ld+json' });
        }
        return;
      }

      // The publish site owns every remaining path, because a node's URL is
      // its own path (§12.6) and cannot be distinguished from an unknown one.
      if (this.site) {
        send = this.#send(req, 'site');
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          send(res, 405, problem('method_not_allowed'), {
            'content-type': 'application/problem+json', allow: 'GET, HEAD',
          });
          return;
        }
        const r = await this.site.handle({ urlPath: path, query: url.searchParams, principal });
        send(res, r.status, r.body, {
          // Content-derived HTML renders no author script (web/markdown.mjs
          // escapes raw HTML), so a strict policy costs nothing and closes the
          // gap if that ever regresses.
          'content-security-policy':
            "default-src 'none'; img-src 'self' data:; style-src 'self'; "
            + "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'",
          'referrer-policy': 'same-origin',
          ...r.headers,
          // Feed autodiscovery without touching the site's own templates.
          link: this.enabled.has('feeds')
            ? `<${base}/feed.atom>; rel="alternate"; type="application/atom+xml", `
              + `<${base}/.well-known/basalt>; rel="service-desc"`
            : `<${base}/.well-known/basalt>; rel="service-desc"`,
        });
        return;
      }

      send(res, 404, problem('not_found', `no surface serves ${path}`),
        { 'content-type': 'application/problem+json' });
    } catch (err) {
      send(res, 500, problem('internal', err?.message), {
        'content-type': 'application/problem+json',
      });
    }
  }

  async #graphql(req, res, { url, principal, body, send }) {
    if (url.pathname.endsWith('/schema.graphql')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        send(res, 405, problem('method_not_allowed'), { allow: 'GET, HEAD' });
        return;
      }
      send(res, 200, printSchema(), { 'content-type': 'application/graphql; charset=utf-8' });
      return;
    }

    let source;
    let variables;
    let operationName;

    if (req.method === 'GET') {
      // The GET form is fine here because every operation is a query; a
      // mutation over GET is the risk that convention exists to avoid, and
      // this schema has none.
      source = url.searchParams.get('query');
      operationName = url.searchParams.get('operationName') ?? undefined;
      const raw = url.searchParams.get('variables');
      if (raw) {
        try {
          variables = JSON.parse(raw);
        } catch {
          send(res, 400, { errors: [{ message: 'variables= is not JSON' }] });
          return;
        }
      }
    } else if (req.method === 'POST') {
      const type = (req.headers['content-type'] ?? '').split(';')[0].trim();
      if (type === 'application/graphql') {
        source = body.toString('utf8');
      } else {
        try {
          const json = JSON.parse(body.toString('utf8') || '{}');
          source = json.query;
          variables = json.variables;
          operationName = json.operationName;
        } catch {
          send(res, 400, { errors: [{ message: 'request body is not JSON' }] });
          return;
        }
      }
    } else {
      send(res, 405, problem('method_not_allowed'), { allow: 'GET, HEAD, POST' });
      return;
    }

    if (typeof source !== 'string' || source.trim() === '') {
      send(res, 400, { errors: [{ message: 'a query is required' }] });
      return;
    }

    const out = await graphql({
      source, variables, operationName, surface: this.surface, principal,
    });
    // A GraphQL response is 200 even when it carries errors: the errors are
    // per-field, and a partial answer is still an answer.
    send(res, 200, out, { 'content-type': 'application/json' });
  }

  /** The machine-readable list of everything this vault speaks (§1.4). */
  discovery(base) {
    const man = this.surface.manifest();
    const s = {};
    if (this.enabled.has('rest')) {
      s.rest = {
        base: `${base}/api/v1`,
        openapi: `${base}/api/v1/openapi.json`,
        spec: 'OpenAPI 3.1',
      };
    }
    if (this.enabled.has('graphql')) {
      s.graphql = {
        endpoint: `${base}/graphql`,
        schema: `${base}/graphql/schema.graphql`,
        methods: ['GET', 'POST'],
        queries_only: true,
      };
    }
    if (this.enabled.has('jsonrpc')) {
      s.jsonrpc = {
        endpoint: `${base}/rpc`,
        version: '2.0',
        describe: 'basalt.operations',
      };
    }
    if (this.enabled.has('mcp')) {
      s.mcp = {
        endpoint: `${base}/mcp`,
        transports: ['streamable-http (JSON only)', 'stdio: basalt mcp'],
        protocol_versions: MCP_VERSIONS,
      };
    }
    if (this.enabled.has('connect')) s.connect = { base, ...connectDescriptor() };
    if (this.enabled.has('webdav')) {
      s.webdav = {
        mount: `${base}/dav/`,
        dav_class: '1',
        read_only: true,
        methods: ['OPTIONS', 'GET', 'HEAD', 'PROPFIND'],
      };
    }
    if (this.enabled.has('feeds')) {
      s.feeds = {
        atom: `${base}/feed.atom`,
        rss: `${base}/feed.xml`,
        sitemap: `${base}/sitemap.xml`,
        opensearch: `${base}/opensearch.xml`,
      };
    }
    if (this.enabled.has('rdf')) {
      s.rdf = {
        jsonld: `${base}/graph.jsonld`,
        turtle: `${base}/graph.ttl`,
        vocabulary: RDF_NS.NS,
      };
    }
    if (this.site) s.html = { home: `${base}/`, note: 'The publish site (§12.6).' };
    return {
      basalt: 1,
      vault: man.vault,
      publish: man.publish,
      index_state: this.surface.state,
      operations: OPERATIONS.map((o) => o.name),
      surfaces: s,
      notes: [
        'Every surface answers for the principal the gatekeeper reduced the request to (§12.1).',
        'A 404 means "no such object" or "you may not discover it" and the two are indistinguishable (§12.3).',
        'All surfaces are read-only: §12 defines a read surface.',
      ],
    };
  }

  landing(base) {
    const d = this.discovery(base);
    const rows = Object.entries(d.surfaces).map(([name, info]) => {
      const first = info.base ?? info.endpoint ?? info.mount ?? info.atom ?? info.jsonld ?? base;
      return `<tr><td><code>${name}</code></td><td><a href="${esc(first)}">${esc(first)}</a></td></tr>`;
    }).join('\n');
    return `<!doctype html>
<meta charset="utf-8">
<title>${esc(d.vault.title ?? d.vault.id)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:44rem;padding:0 1rem}
table{border-collapse:collapse}td{padding:.25rem .75rem .25rem 0}code{font-size:.95em}</style>
<h1>${esc(d.vault.title ?? d.vault.id)}</h1>
<p>A Basalt vault, audience <code>${esc(d.publish.audience)}</code>, index
<code>${esc(d.index_state)}</code>. Everything below is filtered to the principal
this request reduced to.</p>
<table>
${rows}
</table>
<p>Machine-readable: <a href="/.well-known/basalt"><code>/.well-known/basalt</code></a></p>
`;
  }
}

const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const FEEDS = {
  '/feed.atom': { type: 'application/atom+xml; charset=utf-8', body: (s, p, o) => atom(s, p, o) },
  '/feed.xml': { type: 'application/rss+xml; charset=utf-8', body: (s, p, o) => rss(s, p, o) },
  '/sitemap.xml': { type: 'application/xml; charset=utf-8', body: (s, p, o) => sitemap(s, p, o) },
  '/opensearch.xml': {
    type: 'application/opensearchdescription+xml; charset=utf-8',
    body: (s, p, o) => opensearch(s, o),
  },
  '/robots.txt': { type: 'text/plain; charset=utf-8', body: (s, p, o) => robots(s, o) },
};

export const ALL_SURFACES = ['rest', 'graphql', 'jsonrpc', 'mcp', 'connect', 'webdav', 'feeds', 'rdf'];

/** Profile name (INTEROP §10) to the surface it mounts. */
export const PROFILE_SURFACE = {
  'P-REST': 'rest',
  'P-GRAPHQL': 'graphql',
  'P-JSONRPC': 'jsonrpc',
  'P-MCP': 'mcp',
  'P-GRPC': 'connect',
  'P-WEBDAV': 'webdav',
  'P-FEEDS': 'feeds',
  'P-RDF': 'rdf',
  // P-INTEROP is the claim that two or more of the above agree (INTEROP §9).
  // It mounts nothing of its own.
  'P-INTEROP': null,
};

/**
 * The surfaces mounted by default when a manifest declares nothing: the §12
 * read API, and nothing else.
 *
 * Every other surface is an interop *profile* (§14.1) — orthogonal to the
 * conformance levels and not required by any of them — so it is opt-in.
 */
export const DEFAULT_SURFACES = ['rest'];

/**
 * The surfaces a vault's manifest allows.
 *
 * A manifest that lists `publish.interop` bounds what may be mounted, so a
 * vault owner can take a surface off for every deployment of that vault in
 * one edit — the same shape as the §12.2 audience ceiling.
 *
 * A manifest that says nothing gets DEFAULT_SURFACES, **not** everything.
 * Silence means deny throughout this protocol — an unmatched right is denied
 * (§8.4 step 5), an unresolvable subject denies (§8.4), an undeclared
 * audience is `gated` — and a vault written before this annex existed cannot
 * have consented to serving GraphQL, WebDAV, RDF and an MCP endpoint. An
 * operator who wants them says so with --surfaces, or the vault does with
 * `publish.interop`.
 */
export function declaredSurfaces(vault) {
  const declared = vault?.manifest?.publish?.interop;
  if (!Array.isArray(declared)) return new Set(DEFAULT_SURFACES);
  const out = new Set();
  for (const profile of declared) {
    const surface = PROFILE_SURFACE[profile];
    if (surface) out.add(surface);
  }
  return out;
}
