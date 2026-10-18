// The Connect (gRPC-compatible) surface, INTEROP §5.
//
// Unary Connect over HTTP/1.1 with JSON bodies: POST
// /basalt.v1.BasaltRead/GetNode, or the idempotent GET form so the service is
// reachable with curl. `protocol/basalt.proto` is the schema — generate a
// client with buf/connect, or put a Connect-aware proxy in front to speak
// binary gRPC or gRPC-Web, which this process does not (it has no HTTP/2).
//
// The wire shape is deliberately the same JSON the REST surface returns:
// every proto field sets json_name to its own snake_case name, so one
// response shape serves every surface and nothing has to be re-cased.

import { Fault } from './core.mjs';
import { OP_BY_PROTO, OPERATIONS } from './ops.mjs';

export const SERVICE = 'basalt.v1.BasaltRead';

/** Connect error code → HTTP status, from the Connect protocol's table. */
const STATUS = {
  invalid_argument: 400,
  unauthenticated: 401,
  permission_denied: 403,
  not_found: 404,
  unimplemented: 501,
  internal: 500,
};

/**
 * Handle a Connect call. Returns false when the path is not ours.
 *
 * @param {(res, status, body, headers) => void} send
 */
export async function handleConnect(surface, principal, req, res, { body, send, baseUrl }) {
  const url = new URL(req.url, baseUrl ?? 'http://localhost');
  const m = url.pathname.match(/^\/([A-Za-z0-9_.]+)\/([A-Za-z0-9_]+)$/);
  if (!m || m[1] !== SERVICE) return false;

  const op = OP_BY_PROTO.get(m[2]);
  const fail = (code, message) => send(res, STATUS[code] ?? 500, { code, message }, {
    'content-type': 'application/json',
  });

  if (!op) return fail('unimplemented', `${SERVICE}/${m[2]} is not implemented`);

  let message = {};
  if (req.method === 'POST') {
    const type = (req.headers['content-type'] ?? '').split(';')[0].trim();
    if (type && type !== 'application/json' && type !== 'application/connect+json') {
      // Binary gRPC and the proto codec need a proxy or a real gRPC server;
      // saying so beats failing to parse protobuf as JSON.
      return fail('unimplemented', `codec ${type} is not implemented; use application/json`);
    }
    if (body && body.length) {
      try {
        message = JSON.parse(body.toString('utf8'));
      } catch {
        return fail('invalid_argument', 'request body is not JSON');
      }
    }
  } else if (req.method === 'GET') {
    // Connect's idempotent GET: ?encoding=json&message=<json>&connect=v1
    const raw = url.searchParams.get('message');
    if (raw) {
      try {
        message = JSON.parse(raw);
      } catch {
        return fail('invalid_argument', 'message= is not JSON');
      }
    }
  } else {
    return fail('unimplemented', `${req.method} is not allowed`);
  }

  try {
    const data = await op.call(surface, principal, message);
    send(res, 200, data, { 'content-type': 'application/json' });
  } catch (err) {
    const f = err instanceof Fault ? err : new Fault('internal', err?.message);
    fail(f.connect, f.detail ?? f.code);
  }
  return true;
}

/** The service descriptor, for the discovery document. */
export const connectDescriptor = () => ({
  service: SERVICE,
  methods: OPERATIONS.map((o) => ({
    name: o.proto, path: `/${SERVICE}/${o.proto}`, summary: o.summary,
  })),
  codecs: ['json'],
  note: 'Unary only. Binary gRPC and gRPC-Web need a Connect-aware proxy.',
});
