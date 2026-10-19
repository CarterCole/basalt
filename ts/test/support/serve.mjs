// A gatekeeper with every interop surface mounted, for the test suites.
//
// Not a *.test.mjs file on purpose: `npm test` globs those, and a helper that
// exported from a test file would make every importer re-run it.

import { fileURLToPath } from 'node:url';
import { Vault } from '../../src/vault.mjs';
import { FsTransport } from '../../src/transport/fs.mjs';
import { Gatekeeper } from '../../src/gatekeeper.mjs';
import { ALL_SURFACES } from '../../src/serve/router.mjs';

export const VAULT = fileURLToPath(
  new URL('../../../conformance/vaults/minimal/vault', import.meta.url));

export const VAULT_ID = '01JBQ7X8Z4N3VYK9M2T5HRWC6P';

/** Identity comes from a test-only header; §12.1 forbids a client asserting it. */
export async function serve({ interop, mountDeclared = false, ...opts } = {}) {
  const v = new Vault(new FsTransport(VAULT));
  await v.load();
  await v.reindex();
  // §3.1 `publish.interop`: the fixture declares nothing, so a test that
  // wants the manifest to bound the surfaces sets it here.
  if (interop !== undefined) v.manifest.publish = { ...v.manifest.publish, interop };
  const g = new Gatekeeper(v, {
    identify: (req) => req.headers['x-test-principal'] ?? 'anonymous',
    site: null,
    // These suites exist to exercise the interop surfaces, so they mount them
    // explicitly. The production default is the §12 REST API alone; relying
    // on a permissive default here would have hidden that it was permissive.
    //
    // `mountDeclared` turns the override off, for the tests that are about
    // what the manifest and the default actually decide — an explicit
    // `surfaces` set outranks the manifest, so forcing one here would make
    // those tests pass no matter what the bounding logic did.
    ...(mountDeclared ? {} : { surfaces: new Set(ALL_SURFACES) }),
    ...opts,
  });
  await g.listen(0);
  const { port } = g.server.address();
  const origin = `http://127.0.0.1:${port}`;

  const call = async (path, { principal, method = 'GET', body, headers = {} } = {}) => {
    const res = await fetch(origin + path, {
      method,
      headers: { ...(principal ? { 'x-test-principal': principal } : {}), ...headers },
      body,
      redirect: 'manual',
    });
    const text = await res.text();
    let parsed = text;
    if ((res.headers.get('content-type') ?? '').includes('json')) {
      try { parsed = JSON.parse(text); } catch { /* leave as text */ }
    }
    return { status: res.status, body: parsed, text, headers: res.headers };
  };

  const json = (path, payload, principal) => call(path, {
    principal, method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const rpc = async (path, method, params, principal) => {
    const r = await json(path, { jsonrpc: '2.0', id: 1, method, params }, principal);
    return r.body;
  };

  return { v, g, origin, call, json, rpc };
}
