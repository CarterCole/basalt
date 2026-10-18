// The gatekeeper, PROTOCOL §12.
//
// This process holds the only credentials to the store. The bucket stays
// private and never faces the reader, which is what makes §8's inherited
// permissions real rather than advisory.
//
// The gatekeeper is now a thin listener over `serve/router.mjs`: the §12.3
// read surface is one of several protocols mounted on the same vault surface
// (INTEROP §1), and every one of them enforces §8 through the same object.

import http from 'node:http';
import { Router, ALL_SURFACES } from './serve/router.mjs';

export { ALL_SURFACES };

export class Gatekeeper {
  /**
   * @param {import('./vault.mjs').Vault} vault
   * @param {object} [opts]
   * @param {(req: http.IncomingMessage) => string} [opts.identify]
   *   Reduces a request to exactly one principal id (§12.1). The default
   *   returns `anonymous` for everything: authentication is deliberately out
   *   of scope, and a client must never be able to assert its own id.
   * @param {'proxy'|'redirect'} [opts.delivery]
   * @param {Set<string>} [opts.surfaces] which interop surfaces to mount.
   * @param {string} [opts.publicUrl] absolute base for feeds and RDF IRIs.
   * @param {string|null} [opts.cors] an Access-Control-Allow-Origin value.
   */
  constructor(vault, opts = {}) {
    this.vault = vault;
    this.router = new Router(vault, opts);
  }

  /** The principal-scoped view every surface reads through (INTEROP §1.1). */
  get surface() { return this.router.surface; }

  /** Index freshness, reported by every surface as `X-Basalt-Index-State`. */
  get indexState() { return this.router.indexState; }
  set indexState(v) { this.router.indexState = v; }

  handle(req, res) { return this.router.handle(req, res); }

  /** Drop cached index-derived responses; call after a reindex. */
  invalidate() { this.router.invalidate(); }

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
