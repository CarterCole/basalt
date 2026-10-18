# Basalt

**A portable knowledge vault that lives in any key-value object store, with
real per-object access control and fully derived indexes.**

[The protocol](protocol/PROTOCOL.md) · [conformance corpus](conformance/) ·
[reference implementation](ts/)

Obsidian is volcanic glass; basalt is the volcanic rock that cools into
hexagonal columns. This is a publish-and-share system for a markdown vault,
built the way an open format should be: a spec anyone can implement, a
language-neutral test corpus that decides whether they did, and three
implementations held to it.

A vault is **a flat set of key→blob pairs and nothing else**. The storage
layer has to do five things — get, put, delete, list, stat — and everything
above that is content inside the same key space. Point it at a local folder,
an S3 bucket, MinIO, or Cloudflare R2 and it behaves identically, because the
vault carries its own structure.

## The idea in one paragraph

Content lives at its human path and carries its own identity in frontmatter,
so a Basalt vault *is* a plain folder of markdown — openable in Obsidian, a
text editor, `rg` or `git` by tools that have never heard of this spec. Every
index is derived: delete all of them and any conforming implementation
rebuilds them from content alone. Because index generation is specified down
to the byte, two independent implementations given the same content must emit
byte-identical index files, which is what makes conformance a mechanical fact
rather than a matter of opinion. On top of that sits NTFS-style access
control — ordered allow/deny entries with flag-driven inheritance down the
folder tree — enforced by a gatekeeper that holds the only credentials to the
bucket, because no S3-like store can express an inherited deny.

## Three deliverables

- **[The protocol](protocol/PROTOCOL.md)** — the normative spec. Sixteen
  sections covering the transport contract, virtual folders, dual addressing,
  the security model, link resolution, the index formats, canonical
  serialization and the conformance levels.
- **[The conformance corpus](conformance/)** — language-neutral YAML fixtures
  plus whole vaults with expected index output. Every implementation ships a
  runner that loads these; none defines its own expectations for behavior the
  spec covers. `vaults/minimal` is `gated` and exercises the permission
  ceiling; `vaults/demo` is `public` and is what the Pages workflow ships.
- **The implementations** — `ts/` is the reference: the protocol core, the
  gatekeeper, a server-rendered publish site and a static exporter (L0-L4).
  `rust/` and `python/` are held to the same corpus.

## Run it

```bash
cd ts && npm install && npm test
```

Self-check a vault — integrity, index freshness, whether a rebuild reproduces
the stored indexes byte for byte, and who can actually read what:

```bash
node ts/bin/basalt.mjs check --vault conformance/vaults/minimal/vault --principal u:reader --path "Notes/Columns.md"
```

Serve it:

```bash
node ts/bin/basalt.mjs serve --vault conformance/vaults/minimal/vault --port 4380
```

Against an object store, the only change is the transport:

```bash
node ts/bin/basalt.mjs check --bucket my-vault --flavor r2 --endpoint https://ACCOUNT.r2.cloudflarestorage.com
```

## Testing against a real object store

`npm test` is hermetic: the S3 suite skips unless `BASALT_S3_ENDPOINT` is set.
To run it against MinIO in Docker:

```bash
docker run -d --name basalt-minio -p 9000:9000 -e MINIO_ROOT_USER=basalttest -e MINIO_ROOT_PASSWORD=basalttest123 minio/minio:latest server /data
```

```bash
cd ts && BASALT_S3_ENDPOINT=http://127.0.0.1:9000 BASALT_S3_KEY=basalttest BASALT_S3_SECRET=basalttest123 BASALT_S3_FLAVOR=minio npm test
```

The load-bearing case in that suite is **same vault over two transports
yields identical indexes**: §0 claims index generation depends only on
content, and an object store whose `list` order is arbitrary and whose etags
are not content hashes is the thing most likely to disprove it.

Coverage, stated honestly: MinIO is integration-tested. The `s3` and `r2`
flavor presets are exercised in unit tests and against MinIO, but **not**
against real AWS S3 or Cloudflare R2, which need credentials this repo does
not carry.

Two things that real-store testing caught, and which anyone implementing this
spec should know:

- **`delete` cannot report whether the key existed.** S3 answers `204` either
  way; a filesystem can tell you, which is the trap. An implementation
  developed only against a filesystem grows a boolean that silently becomes
  wrong in a bucket. See §1.2.
- **A misconfigured transport returns an empty listing, not an error.** Wrong
  bucket, wrong prefix or the wrong S3 addressing style characteristically
  yields zero keys, which is indistinguishable from an empty vault. Two
  things contain it: the manifest sits at a fixed key and so fails loudly
  under the same misconfiguration (§3.1), and a write pass refuses to replace
  a non-empty index with an empty one (§10.7).

## What the storage layer must do

| Operation | Semantics |
|---|---|
| `get(key)` | whole-object read |
| `put(key, bytes)` | create or replace, atomic per key |
| `delete(key)` | idempotent |
| `list(prefix, delimiter?)` | paginated, **order not guaranteed** |
| `stat(key)` | size, etag, mtime |

Optional, each declared in the manifest: `presign`, `conditional_put`,
`range_get`, `versioning`, `batch_delete`.

Deliberately *not* required: server-side ACLs, directories, multi-key
transactions, or per-object metadata beyond those three fields. Those are the
things S3-like stores disagree about, so the protocol builds over the
intersection rather than the union. A local filesystem satisfies all five
trivially; so does a zip file or a Postgres large-object table.

## Publishing to GitHub Pages

A static host has no gatekeeper, so the ACL model degrades to a build-time
filter: `basalt export` writes only nodes granting **both** `read` and
`publish` to `anonymous` (§8.1), and **rebuilds** the indexes from that subset
rather than copying the vault's own.

```bash
node ts/bin/basalt.mjs export --vault conformance/vaults/demo/vault --out dist --clean
```

```bash
node ts/bin/basalt.mjs export --vault path/to/vault --out dist --base /your-repo --clean
```

`--base` is for a project page at `https://user.github.io/your-repo/`; omit it
for a user or org site. `.github/workflows/pages.yml` does this on push, and
fails the build if a withheld node reaches the output.

The export is a working site with no server behind it: clean URLs via
`<path>/index.html`, a `404.html`, and search that runs in the browser over a
postings file built from the public subset only. `--with-vault` additionally
emits a re-servable filtered vault, because §12.6 makes an export a smaller
vault rather than a different kind of thing.

**What copying the vault directory instead would do:** publish `index/`, which
is built as `system` and therefore knows every private node — every edge into
them, every title. The site would look correct. This is the one mistake in
this codebase that is both easy and unrecoverable, which is why the exporter
rebuilds rather than copies, the gatekeeper refuses to serve `index/` at all
(§12.4), and both the test suite and the CI workflow check for it.

Two things the export deliberately does **not** promise:

- **A private note is unreadable, not undiscoverable.** If a public note says
  `[[Quarterly Layoffs]]`, that link renders as "Restricted" and the target's
  text is never indexed — but the author published the name by typing it in a
  public note, and it is indexed as *that note's* content (§15).
- **A listable folder discloses that its contents exist.** Granting `list` on
  a folder is what produces a 403 rather than a 404 for a note inside it.

## Conformance levels

| Level | Name | Adds |
|---|---|---|
| L0 | Transport | the five operations, key validation |
| L1 | Content | layout, manifest, identity, frontmatter |
| L2 | Index | link resolution, all indexes, canonical bytes |
| L3 | Security | principals, ACL evaluation, traverse |
| L4 | Gatekeeper | HTTP surface, filtering, denial semantics |
| L5 | History | version records, blobs, concurrency |

L0–L2 make a vault readable and indexable, which is all a static site
generator needs. The reference implementation covers L0–L4.

## Two things worth knowing before you trust it

**The indexes are the attack surface.** The link graph and search index
necessarily see every node, so a gatekeeper must re-filter every
index-derived response per principal, and the response cache must be keyed by
the requester's effective subject set. Serving one user's visibility to
another from a cache is the single most likely way a conforming-*looking*
implementation leaks, and the corpus tests it directly.

**Deny is not revocation.** An explicit allow on a node overrides an
inherited deny from its folder — intended NTFS behavior, and what makes "deny
the whole tree, allow this one file" expressible. It also means a tree-wide
deny is not a guarantee about every descendant. A DACL cannot say "everyone
except Carter"; denying `everyone` denies the owner too. To revoke access with
certainty, remove the allow entries or set `protected: true` and grant nothing.

## License

MIT.
