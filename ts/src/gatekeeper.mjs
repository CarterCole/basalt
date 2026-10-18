// The gatekeeper HTTP service, PROTOCOL §12.
//
// This process holds the only credentials to the store. The bucket stays
// private and never faces the reader, which is what makes §8's inherited
// permissions real rather than advisory.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.mjs';
import { pathToKey, parentFolder, isFolder } from './keys.mjs';

const MEDIA = {
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json', '.yaml': 'text/yaml', '.yml': 'text/yaml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8',
};
const mediaFor = (p) => MEDIA[(p.match(/\.[^.]+$/) ?? [''])[0].toLowerCase()]
  ?? 'application/octet-stream';

/**
 * §12.4 forbids ever serving these trees to a non-system principal: they are
 * the index, the ACLs and the principal list, and §8.8 explains why handing
 * them out leaks the private half of the vault.
 */
const NEVER_SERVE = ['meta/', 'index/', 'principals/', 'history/', 'basalt.yaml'];

export class Gatekeeper {
  /**
   * @param {import('./vault.mjs').Vault} vault
   * @param {object} [opts]
   * @param {(req: http.IncomingMessage) => string} [opts.identify]
   *   Reduces a request to exactly one principal id (§12.1). The default
   *   returns `anonymous` for everything: authentication is deliberately out
   *   of scope, and a client must never be able to assert its own id.
   * @param {'proxy'|'redirect'} [opts.delivery]
   */
  constructor(vault, { identify, delivery = 'proxy', site = null } = {}) {
    this.vault = vault;
    this.identify = identify ?? (() => 'anonymous');
    this.delivery = delivery;
    this.site = site;
    this.cache = new Map();
  }

  /**
   * A cache key for index-derived responses (§12.5).
   *
   * It MUST include the principal's effective subject set, or the cache
   * serves one user's visibility to another. This is the single most likely
   * place for a conforming-looking implementation to leak.
   */
  #cacheKey(route, principalId, arg) {
    const subjects = [
      principalId,
      ...[...this.vault.principals.groupsOf(principalId)].sort(),
    ].join(',');
    const h = createHash('sha256').update(subjects).digest('hex').slice(0, 16);
    return `${route}\u0000${h}\u0000${arg ?? ''}`;
  }

  async handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const principal = this.identify(req);
    const send = (status, body, headers = {}) => {
      const state = this.indexState ?? 'fresh';
      res.writeHead(status, {
        'content-type': 'application/json',
        'x-basalt-vault': this.vault.manifest?.vault?.id ?? '',
        'x-basalt-index-state': state,
        'cache-control': 'private, no-store',
        ...headers,
      });
      res.end(typeof body === 'string' || Buffer.isBuffer(body)
        ? body : canonicalJson(body));
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(405, { error: 'method_not_allowed' });
    }

    // Anything outside /api/ belongs to the publish site when one is attached.
    if (this.site && !url.pathname.startsWith('/api/')) {
      const r = await this.site.handle({
        urlPath: url.pathname,
        query: url.searchParams,
        principal,
      });
      res.writeHead(r.status, {
        'x-basalt-vault': this.vault.manifest?.vault?.id ?? '',
        'x-basalt-index-state': this.indexState ?? 'fresh',
        // Content-derived HTML renders no author script (markdown.mjs escapes
        // raw HTML), so a strict policy costs nothing and closes the gap if
        // that ever regresses.
        'content-security-policy':
          "default-src 'none'; img-src 'self' data:; style-src 'self'; " +
          "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'",
        'referrer-policy': 'same-origin',
        'x-content-type-options': 'nosniff',
        ...r.headers,
      });
      res.end(req.method === 'HEAD' ? undefined : r.body);
      return;
    }

    const m = url.pathname.match(/^\/api\/v1\/([a-z]+)(?:\/(.*))?$/);
    if (!m) return send(404, { error: 'not_found' });
    const [, route, rest = ''] = m;
    const target = decodeURIComponent(rest);

    // §12.4: refuse the protocol's own trees outright, before any ACL work.
    if (NEVER_SERVE.some((p) => target === p || target.startsWith(p))) {
      return send(404, { error: 'not_found' });
    }

    try {
      switch (route) {
        case 'manifest': {
          const man = this.vault.manifest;
          return send(200, {
            basalt: man.basalt,
            vault: { id: man.vault.id, title: man.vault.title },
            publish: { audience: man.publish?.audience, home: man.publish?.home },
          });
        }

        case 'node': {
          const r = await this.vault.readNode(principal, target);
          if (r.status !== 200) return send(r.status, { error: errorFor(r.status) });
          return send(200, {
            node: r.node,
            text: r.text,
            links: this.vault.links(principal, target),
          });
        }

        case 'raw': {
          const r = await this.vault.readNode(principal, target);
          if (r.status !== 200) return send(r.status, { error: errorFor(r.status) });

          if (this.delivery === 'redirect' && this.vault.t.capabilities?.has('presign')) {
            // §12.4: a presigned URL is a bearer token that outlives the ACL
            // check that produced it, so the TTL is short and it is never
            // allowed into a shared cache.
            const loc = await this.vault.t.presign(pathToKey(target), { ttlSeconds: 120 });
            return send(302, '', { location: loc, 'cache-control': 'private, no-store' });
          }
          return send(200, r.bytes, { 'content-type': mediaFor(target) });
        }

        case 'list': {
          const folder = target === '' ? '' : (isFolder(target) ? target : target + '/');
          const key = this.#cacheKey('list', principal, folder);
          if (this.cache.has(key)) return send(200, this.cache.get(key));
          const r = this.vault.listFolder(principal, folder);
          if (r.status !== 200) return send(r.status, { error: errorFor(r.status) });
          const body = { folder, entries: r.entries, folders: r.folders };
          this.cache.set(key, body);
          return send(200, body);
        }

        case 'links': {
          const r = this.vault.links(principal, target);
          if (r.status !== 200) return send(r.status, { error: errorFor(r.status) });
          return send(200, { out: r.out, backlinks: r.backlinks });
        }

        case 'search': {
          const q = url.searchParams.get('q') ?? '';
          if (!q) return send(400, { error: 'missing_q' });
          return send(200, this.vault.search(principal, q));
        }

        case 'tree': {
          const key = this.#cacheKey('tree', principal, '');
          if (this.cache.has(key)) return send(200, this.cache.get(key));
          const r = this.vault.tree(principal);
          this.cache.set(key, r);
          return send(200, r);
        }

        case 'effective': {
          const path = url.searchParams.get('path') ?? '';
          const who = url.searchParams.get('principal') ?? principal;
          // §8.7 is a privileged view: seeing someone else's effective rights
          // requires read_acl on the object.
          if (!this.vault.can(principal, path, ['read_acl']).allowed) {
            return send(403, { error: 'forbidden' });
          }
          const e = this.vault.effective(who, path);
          return send(200, {
            principal: who, path, granted: e.granted,
            decisions: e.decisions, failed_at: e.failedAt,
          });
        }

        default:
          return send(404, { error: 'not_found' });
      }
    } catch (err) {
      return send(500, { error: 'internal', detail: err.message });
    }
  }

  /** Drop cached index-derived responses; call after a reindex. */
  invalidate() { this.cache.clear(); }

  listen(port = 4380, host = '127.0.0.1') {
    this.server = http.createServer((req, res) => this.handle(req, res));
    return new Promise((resolve) => {
      this.server.listen(port, host, () => resolve(this.server));
    });
  }

  close() {
    return new Promise((resolve) => this.server
      ? this.server.close(resolve) : resolve());
  }
}

function errorFor(status) {
  return status === 404 ? 'not_found'
    : status === 403 ? 'forbidden'
    : 'error';
}
