// JSON-RPC 2.0 framing, INTEROP §4.1.
//
// Shared by the MCP surface and anything else that wants a method-call shape
// over the same vault surface. Kept separate from MCP because the framing is
// not MCP's: a plain JSON-RPC client can speak to /rpc with no MCP handshake.

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

export const result = (id, value) => ({ jsonrpc: '2.0', id, result: value });

export const error = (id, code, message, data) => ({
  jsonrpc: '2.0', id: id ?? null,
  error: data === undefined ? { code, message } : { code, message, data },
});

/** True for a notification: no id, so no response may be sent. */
export const isNotification = (msg) => msg && msg.id === undefined;

/**
 * Dispatch one parsed message against a method table.
 *
 * Returns the response object, or null when the message was a notification.
 * A handler may throw `{code, message, data}` or an Error; both become a
 * JSON-RPC error object rather than escaping to the transport.
 */
export async function dispatch(methods, msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return error(null, INVALID_REQUEST, 'not a JSON-RPC object');
  }
  if (msg.jsonrpc !== '2.0') {
    return error(msg.id ?? null, INVALID_REQUEST, 'jsonrpc must be "2.0"');
  }
  if (typeof msg.method !== 'string') {
    return error(msg.id ?? null, INVALID_REQUEST, 'method is required');
  }
  // A response or an error flowing back in is not ours to answer.
  if ('result' in msg || 'error' in msg) return null;

  const handler = methods[msg.method];
  if (!handler) {
    return isNotification(msg) ? null
      : error(msg.id, METHOD_NOT_FOUND, `unknown method ${msg.method}`);
  }
  try {
    const value = await handler(msg.params ?? {}, msg);
    return isNotification(msg) ? null : result(msg.id, value ?? {});
  } catch (err) {
    if (isNotification(msg)) return null;
    if (err && typeof err.code === 'number') {
      return error(msg.id, err.code, err.message, err.data);
    }
    return error(msg.id, INTERNAL_ERROR, err?.message ?? 'internal error');
  }
}

/** Parse, dispatch, and return the text to write back (or null). */
export async function handleText(methods, text) {
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    return JSON.stringify(error(null, PARSE_ERROR, 'invalid JSON'));
  }
  if (Array.isArray(msg)) {
    const out = [];
    for (const m of msg) {
      const r = await dispatch(methods, m);
      if (r) out.push(r);
    }
    return out.length ? JSON.stringify(out) : null;
  }
  const r = await dispatch(methods, msg);
  return r ? JSON.stringify(r) : null;
}

/**
 * Run a newline-delimited JSON-RPC loop over a stream pair — the stdio
 * transport MCP clients spawn. Nothing but JSON-RPC may go to stdout, so
 * every diagnostic in this path belongs on stderr.
 */
export function serveStdio(methods, { input = process.stdin, output = process.stdout } = {}) {
  let buffer = '';
  return new Promise((resolve) => {
    input.setEncoding('utf8');
    input.on('data', async (chunk) => {
      buffer += chunk;
      let nl;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        const out = await handleText(methods, line);
        if (out !== null) output.write(out + '\n');
      }
    });
    input.on('end', resolve);
    input.on('close', resolve);
  });
}
