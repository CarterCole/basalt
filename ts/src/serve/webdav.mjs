// The WebDAV surface, INTEROP §6.
//
// This is the surface that makes an ACL-filtered vault mountable: Finder,
// Explorer, GNOME Files, Cyberduck, rclone and davfs2 all speak it, so a
// reader gets a folder containing exactly the nodes they may read while the
// gatekeeper keeps the only credentials to the bucket. Obsidian, VS Code and
// ripgrep then work on the mount with no knowledge of this protocol.
//
// Read-only, DAV class 1: there is no write path in §12, and a class-2 server
// would have to implement LOCK for writes it cannot perform.

import { Fault, mediaFor } from './core.mjs';
import { basename } from '../keys.mjs';

const MOUNT = '/dav';
const ALLOW = 'OPTIONS, GET, HEAD, PROPFIND';

const xml = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

/** Percent-encode a vault path for a DAV href, keeping the separators. */
const href = (path) => MOUNT + '/' + path.split('/').map(encodeURIComponent).join('/');

const httpDate = (iso) => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toUTCString();
};

/** The props this server knows. Anything else requested comes back 404. */
const KNOWN = new Set(['resourcetype', 'getcontentlength', 'getcontenttype',
  'getetag', 'getlastmodified', 'displayname', 'creationdate', 'supportedlock']);

/** Collect the prop names a PROPFIND body asked for, if it named any. */
function requestedProps(body) {
  const text = body?.toString('utf8') ?? '';
  if (!text.trim() || /<[\w-]*:?allprop\b/i.test(text)) return null;
  const block = text.match(/<[\w-]*:?prop\b[^>]*>([\s\S]*?)<\/[\w-]*:?prop>/i);
  if (!block) return null;
  const names = [...block[1].matchAll(/<([\w-]+:)?([\w-]+)\s*\/?>/g)].map((m) => m[2].toLowerCase());
  return names.length ? names : null;
}

function propstat(path, { collection, size, mediaType, etag, mtime, title }, asked) {
  const props = {
    resourcetype: collection ? '<D:collection/>' : '',
    displayname: xml(title ?? basename(path.replace(/\/$/, '')) ?? ''),
    getcontenttype: collection ? null : xml(mediaType),
    getcontentlength: collection ? null : String(size ?? 0),
    getetag: collection ? null : (etag ? xml(etag) : null),
    getlastmodified: httpDate(mtime),
    creationdate: mtime ?? null,
    supportedlock: '',
  };

  const want = asked ?? [...KNOWN];
  const found = [];
  const missing = [];
  for (const name of want) {
    const v = props[name];
    if (v === null || v === undefined) { missing.push(name); continue; }
    found.push(v === '' ? `        <D:${name}/>` : `        <D:${name}>${v}</D:${name}>`);
  }

  let out = `  <D:response>\n    <D:href>${xml(path === '' ? MOUNT + '/' : href(path))}</D:href>\n`
    + '    <D:propstat>\n      <D:prop>\n'
    + found.join('\n') + (found.length ? '\n' : '')
    + '      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n';
  if (missing.length) {
    out += '    <D:propstat>\n      <D:prop>\n'
      + missing.map((n) => `        <D:${n}/>`).join('\n')
      + '\n      </D:prop>\n      <D:status>HTTP/1.1 404 Not Found</D:status>\n    </D:propstat>\n';
  }
  return out + '  </D:response>\n';
}

/**
 * Handle a WebDAV request under /dav. Returns false when the path is not ours.
 *
 * @param {(res, status, body, headers) => void} send
 */
export async function handleWebdav(surface, principal, req, res, { body, send, baseUrl }) {
  const url = new URL(req.url, baseUrl ?? 'http://localhost');
  if (url.pathname !== MOUNT && !url.pathname.startsWith(MOUNT + '/')) return false;

  let target;
  try {
    target = decodeURIComponent(url.pathname.slice(MOUNT.length).replace(/^\//, ''));
  } catch {
    send(res, 400, 'malformed percent-encoding', { 'content-type': 'text/plain' });
    return true;
  }

  const deny = (f) => send(res, f.status, f.code, {
    'content-type': 'text/plain; charset=utf-8', allow: ALLOW,
  });

  if (req.method === 'OPTIONS') {
    send(res, 200, '', {
      dav: '1, 3', allow: ALLOW, 'ms-author-via': 'DAV', 'content-length': '0',
    });
    return true;
  }

  if (req.method === 'PROPFIND') {
    const depth = (req.headers.depth ?? 'infinity').toLowerCase();
    const asked = requestedProps(body);
    const isCollection = target === '' || target.endsWith('/')
      || surface.folders(principal).includes(target + '/');
    const folder = target === '' ? '' : (target.endsWith('/') ? target : target + '/');

    try {
      let out = '<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n';

      if (isCollection) {
        const listing = surface.list(principal, folder);
        out += propstat(folder, {
          collection: true,
          title: folder === '' ? (surface.manifest().vault.title ?? 'vault') : basename(folder.replace(/\/$/, '')),
          mtime: null,
        }, asked);

        if (depth !== '0') {
          const children = depth === 'infinity'
            ? surface.nodes(principal).filter((e) => e.path.startsWith(folder))
            : listing.entries.map((e) => surface.nodes(principal).find((n) => n.path === e.path)).filter(Boolean);
          const folders = depth === 'infinity'
            ? surface.folders(principal).filter((f) => f !== folder && f.startsWith(folder))
            : listing.folders;

          for (const f of folders) {
            out += propstat(f, { collection: true, title: basename(f.replace(/\/$/, '')), mtime: null }, asked);
          }
          for (const e of children) {
            const s = await surface.stat(principal, e.path).catch(() => null);
            out += propstat(e.path, {
              collection: false, size: s?.size ?? e.size, mediaType: mediaFor(e.path),
              etag: e.etag, mtime: s?.mtime, title: basename(e.path),
            }, asked);
          }
        }
      } else {
        const s = await surface.stat(principal, target);
        out += propstat(target, {
          collection: false, size: s.size, mediaType: mediaFor(target),
          etag: s.etag, mtime: s.mtime, title: basename(target),
        }, asked);
      }

      out += '</D:multistatus>\n';
      send(res, 207, out, { 'content-type': 'application/xml; charset=utf-8', dav: '1, 3' });
    } catch (err) {
      deny(err instanceof Fault ? err : new Fault('internal', err?.message));
    }
    return true;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    const isFolder = target === '' || target.endsWith('/')
      || surface.folders(principal).includes(target + '/');
    try {
      if (isFolder) {
        // A browser that follows a mount URL gets something readable rather
        // than a protocol error.
        const folder = target === '' ? '' : (target.endsWith('/') ? target : target + '/');
        const l = surface.list(principal, folder);
        const rows = [
          ...l.folders.map((f) => `<li><a href="${xml(href(f))}">${xml(basename(f.replace(/\/$/, '')))}/</a></li>`),
          ...l.entries.map((e) => `<li><a href="${xml(href(e.path))}">${xml(basename(e.path))}</a> — ${xml(e.title)}</li>`),
        ].join('\n');
        send(res, 200,
          `<!doctype html>\n<meta charset="utf-8">\n<title>${xml(folder || '/')}</title>\n`
          + `<h1>${xml(folder || '/')}</h1>\n<ul>\n${rows}\n</ul>\n`,
          { 'content-type': 'text/html; charset=utf-8', dav: '1, 3' });
        return true;
      }
      const r = await surface.raw(principal, target);
      if (r.redirect) {
        send(res, 302, '', { location: r.redirect, 'cache-control': 'private, no-store' });
        return true;
      }
      send(res, 200, r.bytes, {
        'content-type': r.media_type,
        etag: r.etag ?? undefined,
        'accept-ranges': 'none',
        dav: '1, 3',
      });
    } catch (err) {
      deny(err instanceof Fault ? err : new Fault('internal', err?.message));
    }
    return true;
  }

  // PUT, DELETE, MKCOL, MOVE, COPY, PROPPATCH, LOCK, UNLOCK.
  send(res, 405, `${req.method} is not allowed: this mount is read-only`, {
    allow: ALLOW, dav: '1, 3', 'content-type': 'text/plain; charset=utf-8',
  });
  return true;
}
