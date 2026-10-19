// Plain JSON-RPC 2.0 over HTTP, INTEROP §4.1.
//
// The same operations as MCP without the handshake, for clients that want a
// method call and no agent protocol. Method names are `basalt.<operation>`.

import { Fault } from './core.mjs';
import { OPERATIONS } from './ops.mjs';

export function rpcMethods(surface, principal) {
  const table = {};
  for (const op of OPERATIONS) {
    table[`basalt.${op.name}`] = async (params) => {
      try {
        return await op.call(surface, principal, params ?? {});
      } catch (err) {
        const f = err instanceof Fault ? err : new Fault('internal', err?.message);
        // §12.3's split survives the transport: the code says which of the
        // two denials this is, and `not_found` still covers both "no such
        // object" and "you may not discover it".
        throw { code: f.rpc, message: f.code, data: { status: f.status, detail: f.detail } };
      }
    };
  }
  table['basalt.operations'] = () => ({
    operations: OPERATIONS.map((o) => ({
      method: `basalt.${o.name}`, summary: o.summary, params: o.input,
    })),
  });
  return table;
}
