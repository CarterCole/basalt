// GitHub gist transport, PROTOCOL §1, plus the small GitHub client the gist
// commands share.
//
// A gist is a flat set of non-empty text files, and a vault is a tree of
// arbitrary blobs. The five operations still fit, as long as the mapping is
// honest about what a gist cannot hold:
//
//   - Names are flat. A key becomes one file name by escaping "%" as "%25" and
//     "/" as "%2F" (conformance/cases/gist/mapping.yaml), so `content/Notes/A.md`
//     is the file `content%2FNotes%2FA.md`. Reversible, and a gist someone made
//     by hand with plain names reads back as it looks.
//   - Content is text. The API carries it as a JSON string, so a put of bytes
//     that are not UTF-8, or an empty file, is refused rather than mangled.
//   - It is small. The API returns at most 300 files per gist, so a vault in a
//     gist is for notes, not for a library.
//   - Writes are not atomic. A PATCH carries no precondition, so `ifMatch` is
//     checked against a fresh read and two writers can still pass the check
//     together. The `conditional_put` capability is therefore not claimed.
//
// Writes made inside a batch (Vault.batch) are held back and sent as ONE
// PATCH, so `basalt add` is one gist revision, not one per file. That is the
// same place the git store makes its commit.
//
// The token is read from the environment and sent only to the API host, over
// https (or to a loopback address, for tests). It is never accepted on the
// command line, where it would land in shell history and `ps`.

import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { validateKey } from '../keys.mjs';

export const DEFAULT_API = 'https://api.github.com';
/** The API shows no more than this many files of one gist. */
export const MAX_GIST_FILES = 300;
const MAX_NAME_BYTES = 255;

// ------------------------------------------------------------------- names

/** A vault path (or key) as a gist file name. */
export function encodeName(path) {
  return path.replace(/[%/]/g, (c) => (c === '%' ? '%25' : '%2F'));
}

/** A gist file name as a vault path. Only %2F and %25 mean anything. */
export function decodeName(name) {
  return name.replace(/%(2[Ff]|25)/g, (_, hex) => (hex === '25' ? '%' : '/'));
}

/**
 * The gist id in whatever a person pasted: the id, the page URL, a clone
 * URL. `null` when there is none. A raw-file URL ends in a file name, which is
 * not an id, so it is refused rather than guessed at.
 */
export function parseGistId(input) {
  if (typeof input !== 'string') return null;
  let s = input.trim();
  if (!s) return null;
  s = s.replace(/[#?].*$/, '');
  if (s.includes('://')) {
    try { s = new URL(s).pathname; } catch { return null; }
  } else {
    const scp = /^[^/@]+@[^:/]+:(.+)$/.exec(s);
    if (scp) s = scp[1];
  }
  s = s.replace(/\/+$/, '');
  let last = s.slice(s.lastIndexOf('/') + 1);
  last = last.replace(/\.git$/, '');
  return /^[0-9a-fA-F]{5,64}$/.test(last) ? last.toLowerCase() : null;
}

/**
 * Whether these bytes can be a gist file: non-blank UTF-8 with no NUL.
 * Returns `null` when they can, otherwise why not (`empty` or `not_text`).
 */
export function whyNotText(bytes) {
  const buf = Buffer.from(bytes);
  if (buf.includes(0)) return 'not_text';
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    return 'not_text';
  }
  return text.trim() === '' ? 'empty' : null;
}

// --------------------------------------------------------------------- API

export class GistError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'GistError';
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

const isLoopback = (host) =>
  host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host.endsWith('.localhost');

/**
 * The token to authenticate with: `GITHUB_TOKEN`, then `GH_TOKEN`, then
 * whatever the GitHub CLI has signed in (`gh auth token`), which is where a
 * keyring login lives. `null` when there is none: reading a gist works
 * without one, writing does not.
 */
export async function findToken(env = process.env, { gh = true } = {}) {
  for (const name of ['GITHUB_TOKEN', 'GH_TOKEN']) {
    const v = env[name];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  if (!gh) return null;
  return new Promise((resolve) => {
    execFile('gh', ['auth', 'token'], { timeout: 5000, env, windowsHide: true },
      (err, stdout) => resolve(err ? null : (String(stdout).trim() || null)));
  });
}

/** A gist as the rest of this code sees it. */
function shape(g) {
  const files = new Map();
  for (const [name, f] of Object.entries(g.files ?? {})) {
    if (!f) continue;
    files.set(name, {
      size: f.size ?? (typeof f.content === 'string' ? Buffer.byteLength(f.content) : 0),
      truncated: Boolean(f.truncated),
      rawUrl: f.raw_url ?? null,
      content: !f.truncated && typeof f.content === 'string' ? Buffer.from(f.content, 'utf8') : null,
    });
  }
  return {
    id: g.id,
    url: g.html_url ?? null,
    public: Boolean(g.public),
    description: g.description ?? '',
    updatedAt: g.updated_at ?? null,
    truncated: Boolean(g.truncated),
    files,
  };
}

export class GistApi {
  /**
   * @param {object} [opts]
   * @param {string|null} [opts.token] left out, it is looked up (findToken)
   * @param {string} [opts.apiUrl] GitHub Enterprise, or a test server
   * @param {typeof fetch} [opts.fetch]
   */
  constructor({ token, apiUrl, fetch: fetchImpl, env = process.env } = {}) {
    this.apiUrl = String(apiUrl || env.GITHUB_API_URL || DEFAULT_API).replace(/\/+$/, '');
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.env = env;
    this.token = token; // undefined = look it up on first use
    const u = new URL(this.apiUrl);
    this.origin = u.origin;
    this.secureEnough = u.protocol === 'https:' || isLoopback(u.hostname);
  }

  async #token() {
    if (this.token === undefined) this.token = await findToken(this.env);
    return this.token;
  }

  /** Whether a write could be signed. Cheap after the first call. */
  async canWrite() {
    return Boolean(await this.#token()) && this.secureEnough;
  }

  async #call(method, pathname, body, { write = false } = {}) {
    const headers = {
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'basalt-vault',
    };
    const token = await this.#token();
    if (write && !token) {
      throw new GistError('no_token',
        'writing a gist needs a GitHub token with the gist scope: set GITHUB_TOKEN ' +
        '(or GH_TOKEN), or sign in with `gh auth login`');
    }
    if (token) {
      if (!this.secureEnough) {
        if (write) {
          throw new GistError('insecure_api',
            `${this.apiUrl} is not https, so the token will not be sent to it`);
        }
        // A read of a public or secret gist needs no token; leave it off.
      } else {
        headers.authorization = `Bearer ${token}`;
      }
    }
    if (body !== undefined) headers['content-type'] = 'application/json';

    let res;
    try {
      res = await this.fetch(this.apiUrl + pathname, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw new GistError('network', `could not reach ${this.apiUrl}: ${err.cause?.message ?? err.message}`);
    }
    if (res.ok) return res.status === 204 ? null : res.json();

    let detail = '';
    try { detail = (await res.json()).message ?? ''; } catch { /* not JSON */ }
    const limited = res.headers.get('x-ratelimit-remaining') === '0';
    if (res.status === 404) {
      throw new GistError('not_found', token
        ? 'gist not found (or this token has no access to it)'
        : 'gist not found (or it is private to an account: set GITHUB_TOKEN)', 404);
    }
    if (res.status === 401) {
      throw new GistError('unauthorized', `GitHub rejected the token${detail ? `: ${detail}` : ''}`, 401);
    }
    if (res.status === 429 || (res.status === 403 && limited)) {
      const reset = Number(res.headers.get('x-ratelimit-reset'));
      throw new GistError('rate_limited', 'GitHub rate limit reached' +
        (reset ? `; resets ${new Date(reset * 1000).toISOString()}` : '') +
        (token ? '' : ' (unauthenticated requests get far fewer: set GITHUB_TOKEN)'), res.status);
    }
    if (res.status === 403) {
      throw new GistError('forbidden', `GitHub refused: ${detail || 'forbidden'}` +
        (write ? ' (the token needs the gist scope)' : ''), 403);
    }
    throw new GistError('http', `GitHub answered ${res.status}${detail ? `: ${detail}` : ''}`, res.status);
  }

  /** One gist, with the files it shows inline. */
  async get(id) {
    if (!/^[0-9a-f]{5,64}$/.test(String(id))) {
      throw new GistError('bad_id', `not a gist id: ${id}`);
    }
    return shape(await this.#call('GET', `/gists/${encodeURIComponent(id)}`));
  }

  /** Create a gist. `files` maps a file name to its text. Secret unless `public`. */
  async create({ files, description = '', public: isPublic = false }) {
    const body = { description, public: Boolean(isPublic), files: {} };
    for (const [name, content] of Object.entries(files)) body.files[name] = { content };
    return shape(await this.#call('POST', '/gists', body, { write: true }));
  }

  /**
   * Change a gist: a file name mapped to text sets it, mapped to `null`
   * removes it. One request, so one revision.
   */
  async update(id, { files, description }) {
    const body = {};
    if (description !== undefined) body.description = description;
    if (files) {
      body.files = {};
      for (const [name, content] of Object.entries(files)) {
        body.files[name] = content === null ? null : { content };
      }
    }
    return shape(await this.#call('PATCH', `/gists/${encodeURIComponent(id)}`, body, { write: true }));
  }

  /**
   * A file the listing cut short (over about 1 MB). The raw host is not the
   * API host, so the token is not sent there: a secret gist is readable by
   * anyone holding its URL, and a token has no business on another origin.
   */
  async raw(url) {
    let res;
    try {
      res = await this.fetch(url, { headers: { 'user-agent': 'basalt-vault' }, signal: AbortSignal.timeout(60_000) });
    } catch (err) {
      throw new GistError('network', `could not fetch ${url}: ${err.cause?.message ?? err.message}`);
    }
    if (!res.ok) throw new GistError('http', `fetching ${url} answered ${res.status}`, res.status);
    return Buffer.from(await res.arrayBuffer());
  }

  /** A file's full bytes: inline when the listing had them, else fetched. */
  async content(file) {
    if (file.content) return file.content;
    if (!file.rawUrl) throw new GistError('http', 'the gist did not say where to fetch a truncated file');
    return this.raw(file.rawUrl);
  }
}

// --------------------------------------------------------------- transport

const md5 = (buf) => `"${createHash('md5').update(buf).digest('hex')}"`;

function unsupported(message) {
  const err = new Error(message);
  err.code = 'UNSUPPORTED';
  return err;
}

export class GistTransport {
  /**
   * @param {object} opts
   * @param {string} opts.id the gist (an id or a URL)
   * @param {GistApi} [opts.api]
   * @param {number} [opts.ttlMs] how long a read of the gist is reused. Reads
   *   cost API calls (60 an hour without a token), and a batch always reads
   *   fresh, so this only bounds how stale a long-lived reader may be.
   */
  constructor({ id, api, ttlMs = 30_000 } = {}) {
    const parsed = parseGistId(id);
    if (!parsed) throw new Error(`not a gist id or URL: ${id}`);
    this.id = parsed;
    this.api = api ?? new GistApi();
    this.ttlMs = ttlMs;
    // Nothing a gist offers maps to a capability of §3.1: no presign, no
    // conditional put (see the header), no ranges, no batch delete.
    this.capabilities = new Set();
    this.gist = null;
    this.fetchedAt = 0;
    this.pending = null;
    this.depth = 0;
    this.chain = Promise.resolve();
  }

  get url() { return this.gist?.url ?? `https://gist.github.com/${this.id}`; }

  /** Read the gist now, and refuse one too big for the API to show whole. */
  async ready() {
    await this.#refresh();
  }

  async #refresh() {
    const g = await this.api.get(this.id);
    if (g.truncated) {
      throw new GistError('too_big',
        `gist ${this.id} has more than ${MAX_GIST_FILES} files, which the API will not list; ` +
        'clone it with git instead, or split it');
    }
    this.gist = g;
    this.fetchedAt = Date.now();
    return g;
  }

  async #view() {
    if (!this.gist || Date.now() - this.fetchedAt > this.ttlMs) await this.#refresh();
    return this.gist;
  }

  /** The gist as it will be once the held-back writes land. */
  async #overlay() {
    const g = await this.#view();
    const names = new Map(); // key → file | Buffer
    for (const [name, f] of g.files) names.set(decodeName(name), f);
    for (const [key, v] of this.pending ?? []) {
      if (v === null) names.delete(key);
      else names.set(key, v);
    }
    return { g, names };
  }

  async #bytes(entry) {
    return Buffer.isBuffer(entry) ? entry : this.api.content(entry);
  }

  async get(key) {
    const { names } = await this.#overlay();
    const e = names.get(key);
    return e === undefined ? null : this.#bytes(e);
  }

  async stat(key) {
    const { g, names } = await this.#overlay();
    const e = names.get(key);
    if (e === undefined) return null;
    const bytes = await this.#bytes(e);
    return { size: bytes.length, etag: md5(bytes), mtime: g.updatedAt };
  }

  async list(prefix = '', { delimiter } = {}) {
    const { names } = await this.#overlay();
    const keys = [];
    const prefixes = new Set();
    for (const key of names.keys()) {
      if (!key.startsWith(prefix)) continue;
      if (delimiter) {
        const rest = key.slice(prefix.length);
        const i = rest.indexOf(delimiter);
        if (i !== -1) { prefixes.add(prefix + rest.slice(0, i + 1)); continue; }
      }
      keys.push(key);
    }
    return { keys, prefixes: [...prefixes] };
  }

  async put(key, bytes, { ifMatch } = {}) {
    validateKey(key);
    const buf = Buffer.from(bytes);
    const why = whyNotText(buf);
    if (why) {
      throw unsupported(`a gist holds non-empty text files only; ${key} is ` +
        `${why === 'empty' ? 'empty' : 'not UTF-8 text'}. Keep it in a folder or git store.`);
    }
    const name = encodeName(key);
    if (Buffer.byteLength(name) > MAX_NAME_BYTES) {
      throw unsupported(`${key} makes a gist file name longer than ${MAX_NAME_BYTES} bytes`);
    }

    if (ifMatch !== undefined) {
      // Fresh outside a batch (a batch read fresh when it began): the check is
      // only as good as that read, and a gist has no way to make it atomic.
      if (!this.pending) await this.#refresh();
      const cur = await this.stat(key);
      if (ifMatch !== (cur?.etag ?? null)) {
        const err = new Error(`precondition failed for ${key}`);
        err.code = 'PRECONDITION_FAILED';
        throw err;
      }
    }

    if (this.pending) {
      this.pending.set(key, buf);
      return { size: buf.length, etag: md5(buf), mtime: new Date().toISOString() };
    }
    await this.#send(new Map([[key, buf]]));
    return this.stat(key);
  }

  async delete(key) {
    if (this.pending) { this.pending.set(key, null); return; }
    await this.#send(new Map([[key, null]]));
  }

  /**
   * Group writes into one PATCH, one revision of the gist. Nested batches
   * join the outer one; the writes go out when the outermost ends, even if the
   * work in it failed part-way, because what was written is still wanted.
   */
  async batch(_info, fn) {
    if (this.pending) return fn();
    const run = this.chain.then(async () => {
      await this.#refresh();
      this.pending = new Map();
      let result;
      let failure;
      try {
        result = await fn();
      } catch (err) {
        failure = err;
      }
      const held = this.pending;
      this.pending = null;
      try {
        await this.#send(held);
      } catch (err) {
        if (failure) process.stderr.write(`basalt: could not write the gist: ${err.message}\n`);
        else failure = err;
      }
      if (failure) throw failure;
      return result;
    });
    this.chain = run.catch(() => {});
    return run;
  }

  /** Send held writes as one PATCH, leaving out what would change nothing. */
  async #send(writes) {
    if (!writes.size) return;
    const g = this.gist ?? await this.#refresh();
    const byKey = new Map([...g.files].map(([name, f]) => [decodeName(name), [name, f]]));
    const files = {};
    for (const [key, v] of writes) {
      const had = byKey.get(key);
      if (v === null) {
        if (had) files[had[0]] = null;
        continue;
      }
      if (had && had[1].content && had[1].content.equals(v)) continue;
      // Reuse the name the gist already has, so a file written by hand under
      // an odd spelling is updated and not duplicated beside it.
      files[had ? had[0] : encodeName(key)] = v.toString('utf8');
    }
    if (!Object.keys(files).length) return;
    const after = g.files.size
      + Object.entries(files).filter(([n, c]) => c !== null && !g.files.has(n)).length
      - Object.entries(files).filter(([, c]) => c === null).length;
    if (after > MAX_GIST_FILES) {
      throw new GistError('too_big',
        `that would make ${after} files in the gist; the API shows ${MAX_GIST_FILES}`);
    }
    this.gist = await this.api.update(this.id, { files });
    this.fetchedAt = Date.now();
  }
}
