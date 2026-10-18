// Local filesystem transport, PROTOCOL §1.
//
// A vault on disk is a plain folder: `content/` is openable in Obsidian, a
// text editor, ripgrep or git with no knowledge of this protocol (§3).

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { validateKey } from '../keys.mjs';

export class FsTransport {
  /** @param {string} root absolute path to the vault root */
  constructor(root) {
    this.root = path.resolve(root);
    this.capabilities = new Set(['conditional_put', 'range_get', 'batch_delete']);
  }

  /**
   * Map a key to an absolute path, refusing anything that escapes the root.
   * validateKey already rejects `..` segments, but a transport is the last
   * line of defense and a path-traversal bug here reads the whole disk.
   */
  #resolve(key) {
    const p = path.resolve(this.root, key);
    if (p !== this.root && !p.startsWith(this.root + path.sep)) {
      throw new Error(`key escapes vault root: ${key}`);
    }
    return p;
  }

  async get(key) {
    try {
      return await fs.readFile(this.#resolve(key));
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'EISDIR') return null;
      throw err;
    }
  }

  async put(key, bytes, { ifMatch } = {}) {
    validateKey(key);
    const p = this.#resolve(key);
    if (ifMatch !== undefined) {
      const cur = await this.stat(key);
      if (ifMatch !== (cur?.etag ?? null)) {
        const err = new Error(`precondition failed for ${key}`);
        err.code = 'PRECONDITION_FAILED';
        throw err;
      }
    }
    await fs.mkdir(path.dirname(p), { recursive: true });
    // Write to a temp file and rename, so a reader never sees a half-written
    // object — §1 promises read-after-write for a single key.
    const tmp = `${p}.${process.pid}.${Date.now()}.tmp`;
    await fs.writeFile(tmp, bytes);
    await fs.rename(tmp, p);
    return this.stat(key);
  }

  async delete(key) {
    // §1.2: idempotent, and returns nothing. ENOENT is success here — a
    // filesystem could report prior existence, but promising it would break
    // the moment the same vault moved to an object store.
    try {
      await fs.unlink(this.#resolve(key));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  async stat(key) {
    try {
      const p = this.#resolve(key);
      const st = await fs.stat(p);
      if (!st.isFile()) return null;
      // No cheap server-side etag on a filesystem, so hash the bytes. §10.1
      // treats content_hash as authoritative precisely because etags are not
      // comparable across stores.
      const bytes = await fs.readFile(p);
      return {
        size: st.size,
        etag: `"${createHash('md5').update(bytes).digest('hex')}"`,
        mtime: st.mtime.toISOString(),
      };
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async list(prefix = '', { delimiter } = {}) {
    const keys = [];
    const prefixes = new Set();

    const walk = async (rel) => {
      const abs = rel ? this.#resolve(rel) : this.root;
      let entries;
      try {
        entries = await fs.readdir(abs, { withFileTypes: true });
      } catch (err) {
        if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return;
        throw err;
      }
      for (const e of entries) {
        if (e.name.endsWith('.tmp')) continue;           // in-flight writes
        if (e.name === '.DS_Store' || e.name === '.git') continue;
        const key = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) {
          // Prune subtrees that cannot contain the prefix.
          if (!(key + '/').startsWith(prefix) && !prefix.startsWith(key + '/')) continue;
          await walk(key);
        } else if (e.isFile() && key.startsWith(prefix)) {
          if (delimiter) {
            const rest = key.slice(prefix.length);
            const i = rest.indexOf(delimiter);
            if (i !== -1) { prefixes.add(prefix + rest.slice(0, i + 1)); continue; }
          }
          keys.push(key);
        }
      }
    };

    await walk('');
    return { keys, prefixes: [...prefixes] };
  }
}
