// In-memory transport, PROTOCOL §1. Primarily for tests, and the clearest
// statement of what the five operations have to do.

import { createHash } from 'node:crypto';
import { validateKey, sortUtf8 } from '../keys.mjs';

export class MemoryTransport {
  constructor() {
    this.blobs = new Map();  // key → {bytes, etag, mtime}
    this.capabilities = new Set(['conditional_put', 'range_get', 'batch_delete']);
  }

  async get(key) {
    const e = this.blobs.get(key);
    return e ? e.bytes : null;
  }

  async put(key, bytes, { ifMatch } = {}) {
    validateKey(key);
    if (ifMatch !== undefined) {
      const cur = this.blobs.get(key);
      const curTag = cur?.etag ?? null;
      if (ifMatch !== curTag) {
        const err = new Error(`precondition failed for ${key}`);
        err.code = 'PRECONDITION_FAILED';
        throw err;
      }
    }
    const buf = Buffer.from(bytes);
    const etag = `"${createHash('md5').update(buf).digest('hex')}"`;
    const stat = { size: buf.length, etag, mtime: new Date().toISOString() };
    this.blobs.set(key, { bytes: buf, ...stat });
    return stat;
  }

  async delete(key) {
    // §1.2: returns nothing. The Map knows whether the key was there, but
    // exposing that would let callers depend on an answer S3 cannot give.
    this.blobs.delete(key);
  }

  async stat(key) {
    const e = this.blobs.get(key);
    return e ? { size: e.size, etag: e.etag, mtime: e.mtime } : null;
  }

  /**
   * §1 permits unordered listing, and real stores differ. This transport
   * deliberately yields keys in a shuffled order so that any index code
   * depending on listing order fails here rather than in production.
   */
  async list(prefix = '', { delimiter } = {}) {
    const all = [...this.blobs.keys()].filter((k) => k.startsWith(prefix));
    if (!delimiter) return { keys: shuffle(all), prefixes: [] };

    const keys = [];
    const prefixes = new Set();
    for (const k of all) {
      const rest = k.slice(prefix.length);
      const i = rest.indexOf(delimiter);
      if (i === -1) keys.push(k);
      else prefixes.add(prefix + rest.slice(0, i + 1));
    }
    return { keys: shuffle(keys), prefixes: sortUtf8([...prefixes]) };
  }
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
