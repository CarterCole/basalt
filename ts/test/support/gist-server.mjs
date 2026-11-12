// A stand-in for the part of the GitHub gist API that basalt uses, on a local
// port, so the gist tests never touch the network or anyone's account.
//
// It is deliberately stricter than it needs to be where GitHub's behaviour is
// the reason for a rule in the code under test: a file name with a "/" is
// refused, an empty file is refused, a write without the right token is a 401,
// and a file over `truncateOver` bytes is listed without its content. A bug
// that only shows against the real thing would be a failure here instead.
//
// Not a *.test.mjs file, so `npm test` does not run it on its own.

import http from 'node:http';
import { randomBytes } from 'node:crypto';

export const TOKEN = 'test-token-not-a-real-secret';

export async function gistServer({ truncateOver = 1_000_000, limitReads = false } = {}) {
  const gists = new Map();
  const requests = [];
  let base = '';

  const view = (g) => {
    const files = {};
    for (const [name, content] of g.files) {
      const size = Buffer.byteLength(content);
      const f = { filename: name, size, raw_url: `${base}/raw/${g.id}/${encodeURIComponent(name)}` };
      if (size > truncateOver) f.truncated = true;
      else { f.truncated = false; f.content = content; }
      files[name] = f;
    }
    return {
      id: g.id, html_url: `https://gist.github.com/test/${g.id}`, public: g.public,
      description: g.description, files, updated_at: g.updatedAt,
      truncated: g.files.size > 300,
    };
  };

  const checkFiles = (files, { creating }) => {
    for (const [name, f] of Object.entries(files ?? {})) {
      if (!name || name.includes('/')) return `file name ${JSON.stringify(name)} is not allowed`;
      if (f === null) { if (creating) return 'cannot delete in a create'; continue; }
      if (typeof f?.content !== 'string' || f.content === '') return `${name}: content is empty`;
    }
    return null;
  };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const url = new URL(req.url, 'http://x');
    const auth = req.headers.authorization;
    requests.push({ method: req.method, path: url.pathname, auth: auth ?? null, ua: req.headers['user-agent'] });
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(JSON.stringify(body));
    };
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

    let m;
    if (req.method === 'GET' && (m = /^\/raw\/([0-9a-f]+)\/(.+)$/.exec(url.pathname))) {
      const g = gists.get(m[1]);
      const content = g?.files.get(decodeURIComponent(m[2]));
      if (content === undefined) return send(404, { message: 'Not Found' });
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(content);
    }
    if (limitReads && req.method === 'GET') {
      return send(403, { message: 'API rate limit exceeded' },
        { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '2000000000' });
    }
    if (req.method !== 'GET' && auth !== `Bearer ${TOKEN}`) {
      return send(401, { message: 'Requires authentication' });
    }
    if (req.method === 'POST' && url.pathname === '/gists') {
      const bad = checkFiles(body.files, { creating: true });
      if (bad) return send(422, { message: `Validation Failed: ${bad}` });
      if (!Object.keys(body.files ?? {}).length) return send(422, { message: 'files are required' });
      if (Object.keys(body.files).length > 300) return send(422, { message: 'too many files' });
      const g = {
        id: randomBytes(16).toString('hex'), public: Boolean(body.public),
        description: body.description ?? '', updatedAt: new Date().toISOString(),
        files: new Map(Object.entries(body.files).map(([n, f]) => [n, f.content])),
      };
      gists.set(g.id, g);
      return send(201, view(g));
    }
    if ((m = /^\/gists\/([0-9a-f]+)$/.exec(url.pathname))) {
      const g = gists.get(m[1]);
      if (!g) return send(404, { message: 'Not Found' });
      if (req.method === 'GET') return send(200, view(g));
      if (req.method === 'PATCH') {
        const bad = checkFiles(body.files, { creating: false });
        if (bad) return send(422, { message: `Validation Failed: ${bad}` });
        for (const [n, f] of Object.entries(body.files ?? {})) {
          if (f === null) {
            // GitHub answers an unknown file in a delete with 422, so the code
            // under test must not send one.
            if (!g.files.has(n)) return send(422, { message: `${n}: no such file` });
            g.files.delete(n);
          } else g.files.set(n, f.content);
        }
        if (g.files.size === 0) return send(422, { message: 'a gist needs a file' });
        if (g.files.size > 300) return send(422, { message: 'too many files' });
        if (typeof body.description === 'string') g.description = body.description;
        g.updatedAt = new Date().toISOString();
        g.revisions = (g.revisions ?? 1) + 1;
        return send(200, view(g));
      }
    }
    return send(404, { message: 'Not Found' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;

  return {
    url: base,
    token: TOKEN,
    gists,
    requests,
    /** Put a gist there directly, as if someone had made it on the website. */
    seed(files, { public: isPublic = false, description = '' } = {}) {
      const g = {
        id: randomBytes(16).toString('hex'), public: isPublic, description,
        updatedAt: new Date().toISOString(), revisions: 1,
        files: new Map(Object.entries(files)),
      };
      gists.set(g.id, g);
      return g.id;
    },
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }),
  };
}
