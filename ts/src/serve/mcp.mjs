// The Model Context Protocol surface, INTEROP §4.2.
//
// An MCP client (an agent, an editor, a desktop assistant) gets the vault as
// tools plus resources, over the same JSON-RPC framing as /rpc. The point of
// routing it through the surface rather than handing a model the bucket is
// §8: a model driving this connection sees exactly what its principal sees,
// and `tools/call` on an unreadable node comes back as a tool error, not as
// content.

import { canonicalJson } from '../canonical.mjs';
import { Fault } from './core.mjs';
import { OPERATIONS, OP_BY_NAME } from './ops.mjs';
import { INVALID_PARAMS } from './jsonrpc.mjs';

/** Versions this server speaks, newest first (INTEROP §4.2.1). */
export const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
export const MCP_LATEST = MCP_VERSIONS[0];

/** MCP's own "resource not found", from the spec's error examples. */
const RESOURCE_ERROR = -32002;

const TOOL_PREFIX = 'basalt_';

const INSTRUCTIONS = `This server exposes one Basalt vault — a markdown knowledge
vault in an object store. Every call is evaluated against the vault's access
control list for the principal this connection was opened as, so the tools
return that principal's view and nothing else. A node that is missing and a
node that exists but may not be discovered are deliberately indistinguishable.

Start with basalt_tree or basalt_search to find paths, then basalt_node to read
one. basalt_links gives the graph around a node; an edge whose target reads
"redacted" points at a node this principal may not see, and is kept rather than
dropped so the graph stays honest.`;

const uriFor = (vaultId, path) =>
  `basalt://${vaultId}/${path.split('/').map(encodeURIComponent).join('/')}`;

function pathFromUri(vaultId, uri) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    throw { code: INVALID_PARAMS, message: `not a URI: ${uri}` };
  }
  if (u.protocol !== 'basalt:') {
    throw { code: INVALID_PARAMS, message: `unsupported scheme ${u.protocol}` };
  }
  // basalt://<vault>/<path>: the host is the vault id, which a client holding
  // several vaults open needs in order to not cross them.
  if (u.hostname && vaultId && u.hostname.toLowerCase() !== vaultId.toLowerCase()) {
    throw { code: RESOURCE_ERROR, message: `resource belongs to another vault: ${u.hostname}` };
  }
  return decodeURIComponent(u.pathname.replace(/^\//, ''));
}

const mimeFor = (entry, mediaType) =>
  entry?.kind === 'note' ? 'text/markdown' : mediaType ?? 'application/octet-stream';

/** The MCP tool list, projected from the shared operation table. */
export function mcpTools() {
  return OPERATIONS.map((op) => ({
    name: TOOL_PREFIX + op.name,
    description: op.summary,
    inputSchema: op.input,
  }));
}

/**
 * Build the method table for one principal.
 *
 * Stateless by design: the HTTP transport builds a table per request so the
 * principal cannot outlive the request that established it (§12.1), and the
 * stdio transport builds one for the life of the process.
 */
export function mcpMethods(surface, principal, { serverName = 'basalt', serverVersion = '1.0.0' } = {}) {
  const vaultId = surface.vaultId;

  const callOp = async (op, args) => op.call(surface, principal, args ?? {});

  return {
    initialize: (params) => {
      const asked = params?.protocolVersion;
      // §4.2.1: echo a version we both speak, else answer with ours and let
      // the client decide. Silently pretending to speak the client's version
      // is how a handshake turns into a mystery later.
      const version = MCP_VERSIONS.includes(asked) ? asked : MCP_LATEST;
      return {
        protocolVersion: version,
        capabilities: {
          tools: { listChanged: false },
          resources: { listChanged: false, subscribe: false },
        },
        serverInfo: {
          name: serverName,
          version: serverVersion,
          title: `Basalt vault ${surface.manifest().vault.title ?? vaultId}`,
        },
        instructions: INSTRUCTIONS,
      };
    },

    'notifications/initialized': () => null,
    'notifications/cancelled': () => null,
    ping: () => ({}),

    'tools/list': () => ({ tools: mcpTools() }),

    'tools/call': async (params) => {
      const raw = params?.name ?? '';
      const op = OP_BY_NAME.get(raw.startsWith(TOOL_PREFIX) ? raw.slice(TOOL_PREFIX.length) : raw);
      if (!op) throw { code: INVALID_PARAMS, message: `unknown tool ${raw}` };
      try {
        const data = await callOp(op, params?.arguments);
        return {
          content: [{ type: 'text', text: canonicalJson(data) }],
        };
      } catch (err) {
        // A denial is a tool result, not a transport error: the model asked a
        // reasonable question and the answer is "you may not see that".
        const f = err instanceof Fault ? err : new Fault('internal', err?.message);
        return {
          isError: true,
          content: [{
            type: 'text',
            text: canonicalJson({ error: f.code, status: f.status, detail: f.detail }),
          }],
        };
      }
    },

    'resources/list': (params) => {
      const entries = surface.nodes(principal);
      const cursor = Math.max(0, Number(params?.cursor ?? 0) || 0);
      const page = entries.slice(cursor, cursor + 100);
      const out = {
        resources: page.map((e) => ({
          uri: uriFor(vaultId, e.path),
          name: e.path,
          title: e.title,
          mimeType: mimeFor(e, null),
          size: e.size ?? 0,
        })),
      };
      if (cursor + page.length < entries.length) out.nextCursor = String(cursor + page.length);
      return out;
    },

    'resources/templates/list': () => ({
      resourceTemplates: [{
        uriTemplate: 'basalt://{vault}/{path}',
        name: 'vault-node',
        title: 'A node in a Basalt vault',
        description: 'The bytes of one node, if the principal holds `read` on it (§8.1).',
      }],
    }),

    'resources/read': async (params) => {
      const uri = params?.uri;
      if (typeof uri !== 'string') throw { code: INVALID_PARAMS, message: 'uri is required' };
      const path = pathFromUri(vaultId, uri);
      try {
        const r = await surface.node(principal, path);
        const mimeType = mimeFor(r.node, r.media_type);
        const content = r.text !== null && r.text !== undefined
          ? { uri, mimeType, text: r.text }
          : { uri, mimeType, blob: Buffer.from(r.bytes).toString('base64') };
        return { contents: [content] };
      } catch (err) {
        const f = err instanceof Fault ? err : new Fault('internal', err?.message);
        throw { code: RESOURCE_ERROR, message: f.code, data: { uri, status: f.status } };
      }
    },
  };
}
