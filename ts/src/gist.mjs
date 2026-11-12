// Moving folders to and from GitHub gists: `basalt gist export` and
// `basalt gist import`.
//
// These are copies between a vault, in whatever store it lives, and one gist.
// They are not sync: nothing is merged, and an import never overwrites.
//
//   export  reads a folder of the vault and writes its text files to a gist.
//           A gist is flat, so a file's path inside the folder becomes one file
//           name (encodeName). Anything a gist cannot hold, a binary file or an
//           empty one, is left out and reported by name, never dropped silently.
//   import  reads every file of a gist and stores each as a NEW object under a
//           folder of the vault (§12.7): it gets an id, and is refused, not
//           replaced, if the path is taken. Notes keep their text, and take a
//           new id.
//
// Exporting sends notes to GitHub. A secret gist is unlisted, not private:
// anyone with its URL can read it, and `audience: private` in basalt.yaml is
// enforced by a basalt server, not by GitHub. So secret is the default, public
// has to be asked for, and `dryRun` says what would be sent before it is.

import { CONTENT, keyToPath, isValidKey, sortUtf8 } from './keys.mjs';
import { storeObject } from './store.mjs';
import {
  GistError, encodeName, decodeName, whyNotText, MAX_GIST_FILES,
} from './transport/gist.mjs';

const MAX_NAME_BYTES = 255;
const DEFAULT_DESCRIPTION = 'Exported from a Basalt vault';

/** "Notes" → "Notes/", "/" or "" → "" (the whole vault). */
export function folderPath(input) {
  const f = String(input ?? '').replace(/^\/+/, '');
  return f === '' || f.endsWith('/') ? f : `${f}/`;
}

/**
 * What a folder would send.
 *
 * @returns {Promise<{files: {name, path, bytes}[], skipped: {path, reason}[], withheld: number}>}
 *   `files` in name order; `skipped` are the ones a gist cannot hold, with
 *   `empty`, `not_text`, `name_too_long` or `invalid_key`; `withheld` counts those a
 *   principal may not read (not named, since naming them would tell).
 */
export async function collect(vault, { folder = '', whole = false, principal = null } = {}) {
  const prefix = whole ? '' : CONTENT + folder;
  const { keys } = await vault.t.list(prefix);
  const out = { files: [], skipped: [], withheld: 0 };
  for (const key of sortUtf8(keys.filter((k) => k.startsWith(prefix)))) {
    const path = whole ? key : keyToPath(key);
    // A key §1.1 forbids (a decomposed macOS file name, say) is not an object
    // of the vault: it is in no index. Say so, rather than send or lose it.
    if (!isValidKey(key)) { out.skipped.push({ path, reason: 'invalid_key' }); continue; }
    if (principal !== null && !vault.can(principal, keyToPath(key) ?? key, ['read']).allowed) {
      out.withheld++;
      continue;
    }
    const bytes = await vault.t.get(key);
    if (bytes === null) continue; // raced with a delete
    const why = whyNotText(bytes);
    if (why) { out.skipped.push({ path, reason: why }); continue; }
    const name = encodeName(whole ? key : path.slice(folder.length));
    if (Buffer.byteLength(name) > MAX_NAME_BYTES) {
      out.skipped.push({ path, reason: 'name_too_long' });
      continue;
    }
    out.files.push({ name, path, bytes: Buffer.from(bytes) });
  }
  return out;
}

/**
 * Send a folder (or, with `whole`, every key of the vault, which makes a gist
 * that `--gist ID` can open as a vault) to a gist.
 *
 * @param {import('./vault.mjs').Vault} vault
 * @param {object} args
 * @param {string} [args.folder] "Projects/Basalt/"; "" is every content file
 * @param {boolean} [args.whole] the whole vault, keys and all (operator only)
 * @param {import('./transport/gist.mjs').GistApi} args.api
 * @param {string} [args.update] an existing gist to write into, not a new one
 * @param {boolean} [args.prune] with `update`, remove the gist's files the
 *   export does not have
 * @param {boolean} [args.public] a public gist. New gists only: GitHub does
 *   not let a gist change sides
 * @param {string} [args.description]
 * @param {string|null} [args.principal] send only what this principal may read
 * @param {boolean} [args.dryRun] work out what would go and send nothing
 */
export async function exportToGist(vault, {
  folder = '', whole = false, api, update, prune = false, public: isPublic = false,
  description, principal = null, dryRun = false,
}) {
  if (whole && principal !== null) {
    throw new Error('--whole copies the vault as it is, ACLs and all; it is for the operator, ' +
      'so it does not take --principal');
  }
  if (update && isPublic) {
    throw new Error('--public chooses the visibility of a NEW gist; a gist cannot change sides, ' +
      'so it does not go with --update');
  }
  if (prune && !update) throw new Error('--prune is for --update');

  const picked = await collect(vault, { folder, whole, principal });
  const base = { count: picked.files.length, skipped: picked.skipped, withheld: picked.withheld,
    names: picked.files.map((f) => f.name), bytes: picked.files.reduce((n, f) => n + f.bytes.length, 0) };
  if (!picked.files.length) {
    throw new Error(`nothing to export from ${whole ? 'the vault' : folder === '' ? 'the vault' : folder}` +
      (picked.skipped.length ? ` (${picked.skipped.length} file(s) are not text a gist can hold)` : ''));
  }
  if (picked.files.length > MAX_GIST_FILES) {
    throw new Error(`${picked.files.length} files is more than a gist shows (${MAX_GIST_FILES}); ` +
      'export a smaller folder');
  }
  if (dryRun) return { ...base, dryRun: true, public: Boolean(isPublic) };

  const text = Object.fromEntries(picked.files.map((f) => [f.name, f.bytes.toString('utf8')]));

  if (!update) {
    const g = await api.create({
      files: text, description: description ?? DEFAULT_DESCRIPTION, public: isPublic,
    });
    return { ...base, id: g.id, url: g.url, public: g.public, created: true };
  }

  const g = await api.get(update);
  if (g.truncated) {
    throw new GistError('too_big', `gist ${update} has more than ${MAX_GIST_FILES} files, ` +
      'which the API will not list, so it cannot be updated safely');
  }
  const changes = {};
  let unchanged = 0;
  for (const [name, content] of Object.entries(text)) {
    const had = g.files.get(name);
    if (had?.content && had.content.toString('utf8') === content) unchanged++;
    else changes[name] = content;
  }
  const extra = [...g.files.keys()].filter((n) => !(n in text));
  if (prune) for (const n of extra) changes[n] = null;
  const set = Object.values(changes).filter((c) => c !== null).length;
  const removed = Object.values(changes).filter((c) => c === null).length;
  const result = {
    ...base, id: g.id, url: g.url, public: g.public, updated: true,
    written: set, removed, unchanged, left: prune ? [] : extra,
  };
  if (!set && !removed && description === undefined) return { ...result, updated: false };
  const after = await api.update(update, { files: changes, description });
  return { ...result, url: after.url ?? g.url };
}

/**
 * Store every file of a gist as a new object under `to`.
 *
 * One file that cannot be stored (a taken path, a name that is not a valid
 * path, a principal without `create_child`) is reported and the rest still go.
 * On a git store the whole import is one commit.
 *
 * @returns {Promise<{gist: object, stored: object[], refused: {name, error}[]}>}
 */
export async function importFromGist(vault, {
  api, id, to, principal = null, provenance, log = () => {},
}) {
  const g = await api.get(id);
  if (g.truncated) {
    throw new GistError('too_big', `gist ${id} has more than ${MAX_GIST_FILES} files, ` +
      'which the API will not list; clone it with git and add the files instead');
  }
  const gist = { id: g.id, url: g.url, public: g.public, description: g.description };
  const stored = [];
  const refused = [];
  const names = sortUtf8([...g.files.keys()]);
  if (!names.length) return { gist, stored, refused };

  await vault.batch({
    message: () => `Import ${stored.length} file${stored.length === 1 ? '' : 's'} from gist ${g.id}`,
    trailers: { ...(principal ? { 'Basalt-Principal': principal } : {}), 'Basalt-Source': `gist:${g.id}` },
  }, async () => {
    for (const name of names) {
      const rel = decodeName(name).normalize('NFC');
      try {
        const bytes = await api.content(g.files.get(name));
        const r = await storeObject(vault, {
          principal, path: to + rel, bytes, provenance, reindex: false,
        });
        stored.push(r);
        log(r, name);
      } catch (err) {
        refused.push({ name, error: err.message });
      }
    }
    if (stored.length) await vault.reindex({ write: true });
  });
  return { gist, stored, refused };
}
