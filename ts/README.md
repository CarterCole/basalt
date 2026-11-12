# basalt-vault

The reference implementation of [the Basalt Protocol v1](https://github.com/CarterCole/basalt/blob/main/protocol/PROTOCOL.md):
a portable knowledge vault that lives in a local folder, a git repository, or
any S3-compatible object store (AWS S3, MinIO, Cloudflare R2), with NTFS-style
inherited permissions and fully derived link and search indexes.

A vault is a plain folder of markdown that Obsidian, a text editor or `git`
can open without knowing this package exists. Every index is derived from that
content, byte for byte, so independent implementations agree by test: this
package, the [Rust crate](https://crates.io/crates/basalt-vault) and the
[Python package](https://pypi.org/project/basalt-vault/) all pass the same
[conformance corpus](https://github.com/CarterCole/basalt/tree/main/conformance).

**Conformance:** L0–L4, every interop profile.

## Install

```bash
npm install -g basalt-vault
```

This installs the `basalt` command. Node 20 or later. The AWS SDK comes in as
an optional dependency, so `npm install --omit=optional` gives you folders and
git with no cloud code at all.

## The command

```bash
basalt check --vault ./my-vault                      # self-check (§14.3)
basalt index --vault ./my-vault --write              # rebuild every index
basalt add notes/idea.md --vault ./my-vault          # store a new object, never overwrite
basalt serve --vault ./my-vault --port 4380          # gatekeeper, interop surfaces and publish site
basalt mcp   --vault ./my-vault --principal u:me     # MCP server over stdio
basalt export --vault ./my-vault --out dist          # static publish site
```

Each command takes `--vault DIR`, `--git DIR` or `--bucket B` to pick the
store. `basalt --help` lists every command and option.

`basalt serve` puts eight protocols on one listener, all held to the same
access control: REST with OpenAPI, GraphQL, MCP, JSON-RPC, gRPC/Connect,
WebDAV, RDF and feeds. `curl localhost:4380/.well-known/basalt` lists what it
speaks.

## As a library

```js
import { Vault } from 'basalt-vault';
import { FsTransport } from 'basalt-vault/transport/fs';

const vault = new Vault(new FsTransport('./my-vault'));
await vault.load();
await vault.reindex();

const { hits } = vault.search('everyone', 'columns');
const node = await vault.readNode('everyone', hits[0].path);
console.log(node.status, node.text);
```

Every read takes a principal and returns that principal's view: a node it may
not discover answers exactly as a missing one does. The other transports are
`basalt-vault/transport/git`, `basalt-vault/transport/s3` and
`basalt-vault/transport/memory`.

## More

The [project README](https://github.com/CarterCole/basalt#readme) covers
permissions, storing notes and files, keeping a vault in git, publishing to
GitHub Pages, and what to know before you trust it.

## License

MIT
