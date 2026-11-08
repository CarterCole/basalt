// The write operations, PROTOCOL §12.7.
//
// Kept apart from ops.mjs on purpose. ops.mjs is "every read operation", and
// its table is projected into REST, GraphQL, JSON-RPC, MCP and Connect at
// once, which is exactly what keeps those five honestly equivalent. A write
// must not arrive on all of them by accident: it is offered by the one
// transport where the caller is a local process the operator started and
// named a principal for (`basalt mcp --writable`), and nowhere else.
//
// Same rule as the reads, though: no behaviour here. Authorization, collision
// handling and identity all live in store.mjs; this file only turns an
// argument object into bytes and tells the surface its cache is stale.

import { Fault } from './core.mjs';
import { StoreFault, MAX_STORE_BYTES, storeObject } from '../store.mjs';

const S = (description) => ({ type: 'string', description });

const bad = (detail) => new Fault('bad_request', detail);

/** Strict base64: Buffer.from() would silently skip garbage and truncate. */
function decodeBase64(value) {
  if (typeof value !== 'string') throw bad('base64 must be a string');
  const s = value.replace(/\s+/g, '');
  if (s.length > Math.ceil(MAX_STORE_BYTES / 3) * 4) {
    throw new StoreFault('too_large', 413, `over the ${MAX_STORE_BYTES} byte limit`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
    throw bad('base64 must be the bare encoding of the bytes, not a data: URI');
  }
  return Buffer.from(s, 'base64');
}

/**
 * Store one new object as `principal`, through the surface.
 *
 * The surface's cache holds index-derived answers keyed by subject set
 * (§12.5); a successful store changes those answers for everyone, so it is
 * dropped. It is dropped on failure too: a store that wrote the object and
 * then failed to refresh the indexes has still changed what is on disk.
 *
 * `who` is the connection's agent, account and client, fixed by the operator
 * and the handshake. It is a separate argument from `args` on purpose: `args`
 * is whatever the model sent, and the model does not get to say who it is.
 */
export async function storeThrough(surface, principal, args = {}, who = {}) {
  const { path, text, base64, title, alt } = args;
  if ((text === undefined) === (base64 === undefined)) {
    throw bad('give exactly one of text or base64');
  }
  let bytes;
  if (text !== undefined) {
    if (typeof text !== 'string') throw bad('text must be a string');
    bytes = Buffer.from(text, 'utf8');
  } else {
    bytes = decodeBase64(base64);
  }
  try {
    const stored = await storeObject(surface.vault, {
      principal, path, bytes, title, alt, provenance: who,
    });
    surface.state = 'fresh';
    // Ready to paste into a note. The path form is unambiguous even when the
    // same filename exists elsewhere in the vault (PROTOCOL §9.3).
    const target = stored.kind === 'note' ? stored.path.replace(/\.(md|markdown)$/i, '') : stored.path;
    return {
      ...stored,
      link: stored.kind === 'asset' ? `![[${target}]]` : `[[${target}]]`,
    };
  } finally {
    surface.invalidate();
  }
}

export const WRITE_OPERATIONS = [
  {
    name: 'store',
    summary:
      'Store a NEW note, image or other file in the vault. The extension of `path` decides ' +
      'what it is: .md is a note; .png, .jpg, .pdf and the like are assets; .json/.yaml are ' +
      'data. Give `text` for anything that is UTF-8 text, `base64` for binary. Never ' +
      'overwrites: a path that already exists is a conflict, so choose another. Needs ' +
      '`create_child` on the folder. Do not write a `basalt:` block: the id is assigned, ' +
      'and the vault stamps who stored it (`created_by`: the agent, the account and the ' +
      'credentials behind them), replacing anything you put there. Returns the id and a ' +
      '`link` you can paste into a note.',
    input: {
      type: 'object',
      properties: {
        path: S('Where to put it, relative to the vault root, e.g. "Notes/Idea.md" or ' +
          '"Assets/photo.png". Files other than notes must be inside a folder.'),
        text: S('The content, for a note or other UTF-8 text file. Not with base64.'),
        base64: S('The content, base64-encoded, for an image or any binary file. Not with text.'),
        title: S('A note\'s frontmatter title (if it has none), or an asset\'s display title.'),
        alt: S('Alt text for an image or other asset.'),
      },
      required: ['path'],
      additionalProperties: false,
    },
    // MCP tool annotations: this adds an object and changes nothing that
    // exists, which is a stronger statement than most write tools can make.
    annotations: {
      readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false,
    },
    call: (s, p, a, who) => storeThrough(s, p, a, who),
  },
];

export const WRITE_BY_NAME = new Map(WRITE_OPERATIONS.map((o) => [o.name, o]));
