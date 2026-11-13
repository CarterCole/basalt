# Basalt

**A portable knowledge vault that lives in any key-value object store, with
real per-object access control and fully derived indexes.**

[The protocol](https://github.com/CarterCole/basalt/blob/main/protocol/PROTOCOL.md) · [conformance corpus](https://github.com/CarterCole/basalt/tree/main/conformance/) ·
[reference implementation](https://github.com/CarterCole/ts-basalt)

Obsidian is volcanic glass; basalt is the volcanic rock that cools into
hexagonal columns. This is a publish-and-share system for a markdown vault,
built the way an open format should be: a spec anyone can implement, a
language-neutral test corpus that decides whether they did, and three
implementations held to it.

A vault is **a flat set of key→blob pairs and nothing else**. The storage
layer has to do five things — get, put, delete, list, stat — and everything
above that is content inside the same key space. Point it at a local folder,
a git repository, an S3 bucket, MinIO, or Cloudflare R2 and it behaves
identically, because the vault carries its own structure.

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

- **[The protocol](https://github.com/CarterCole/basalt/blob/main/protocol/PROTOCOL.md)** — the normative spec. Seventeen
  sections covering the transport contract, virtual folders, dual addressing,
  the security model, link resolution, the index formats, canonical
  serialization and the conformance levels, plus
  **[the interoperability annex](https://github.com/CarterCole/basalt/blob/main/protocol/INTEROP.md)** and
  **[the gRPC schema](https://github.com/CarterCole/basalt/blob/main/protocol/basalt.proto)** for the protocols a gatekeeper
  speaks beyond its own.
- **[The conformance corpus](https://github.com/CarterCole/basalt/tree/main/conformance/)** — language-neutral YAML fixtures
  plus whole vaults with expected index output. Every implementation ships a
  runner that loads these; none defines its own expectations for behavior the
  spec covers. `vaults/minimal` is `gated` and exercises the permission
  ceiling; `vaults/demo` is `public` and is what the Pages workflow ships.
- **The implementations** — `ts/` is the reference: the protocol core, the
  gatekeeper, every interop surface, a server-rendered publish site and a
  static exporter (L0-L4, all profiles). `rust/` is held to the same corpus
  and serves two of the surfaces itself (L0-L4, `P-REST`, `P-MCP`,
  `P-INTEROP`), which is what makes the equivalence claim cross-language
  rather than internal. `python/` is L0-L4 with no profiles yet, plus one
  thing that is not the protocol and exists only there: optional topic search
  (`basalt find`, behind the `topics` extra), outside the corpus and never
  written to a vault. All three can [store new objects](#storing-notes-images-and-files),
  [keep a vault in git](#keeping-a-vault-in-git) and
  [move folders to and from GitHub gists](#folders-to-and-from-github-gists),
  and run the same corpus cases for creating objects and for the gist name
  mapping.

## Install

Each implementation is published as `basalt-vault`, and the command it
installs is `basalt` in all three.

| | Install | With S3, MinIO and R2 |
|---|---|---|
| TypeScript (the reference; MCP server and publish site) | `npm install -g basalt-vault` | included, as optional dependencies |
| Rust | `cargo install basalt-vault` | `cargo install basalt-vault --features s3` |
| Python | `pip install basalt-vault` | `pip install 'basalt-vault[s3]'` |

Gist import and export is included in all three. In Rust it is the default
`gist` feature (a native `ureq` + rustls client, no `curl`);
`--no-default-features` builds the core protocol without it.

As a library: `npm install basalt-vault`, `cargo add basalt-vault` (imported
as `basalt`), or `pip install basalt-vault` (imported as `basalt`).

## Run it

From a checkout:

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

That one listener speaks eight protocols over the same vault. Ask it what it
speaks:

```bash
curl -s localhost:4380/.well-known/basalt | jq .surfaces
```

## Eight ways in, one set of permissions

A vault is a format, so the question is not "what is our API" but "what can
already read this". Each surface is a translation layer with no behaviour of
its own — [the annex](https://github.com/CarterCole/basalt/blob/main/protocol/INTEROP.md) specifies them, and one test suite
asks all of them the same questions and compares the answers.

| Surface | Endpoint | What already talks it |
|---|---|---|
| **REST** + OpenAPI 3.1 | `/api/v1`, `/api/v1/openapi.json` | anything HTTP; generated clients |
| **GraphQL** | `/graphql`, SDL at `/graphql/schema.graphql` | web apps, Relay/Apollo, codegen |
| **JSON-RPC 2.0** | `/rpc` | method-call clients, no handshake |
| **MCP** | `/mcp`, or `basalt mcp` over stdio | Claude, editors, agent runtimes |
| **gRPC / Connect** | `/basalt.v1.BasaltRead/*` + [`basalt.proto`](https://github.com/CarterCole/basalt/blob/main/protocol/basalt.proto) | buf/connect clients, any language |
| **WebDAV** (read-only) | `/dav/` | Finder, Explorer, GNOME Files, Cyberduck, `rclone`, `davfs2` |
| **Atom / RSS / sitemap / OpenSearch** | `/feed.atom`, `/feed.xml`, `/sitemap.xml`, `/opensearch.xml` | NetNewsWire, Thunderbird, crawlers, browser search bars |
| **JSON-LD / Turtle** | `/graph.jsonld`, `/graph.ttl` | triple stores, SPARQL engines, reasoners |

The WebDAV mount is the one that surprises people: mount it and Obsidian, VS
Code, `rg` and Quick Look all work on exactly the subset that principal may
read, while the gatekeeper keeps the only credentials to the bucket. No other
mainstream protocol hands a reader a *filtered filesystem*.

Print the machine-readable descriptions without starting a server:

```bash
node ts/bin/basalt.mjs schema openapi --vault conformance/vaults/demo/vault
```

```bash
node ts/bin/basalt.mjs schema graphql
```

Point an MCP client at a vault:

```bash
node ts/bin/basalt.mjs mcp --vault conformance/vaults/demo/vault --principal u:carter
```

Mount it read-only (macOS: Finder → Go → Connect to Server):

```bash
rclone mount :webdav,url=http://localhost:4380/dav: /tmp/vault --read-only
```

Serve a subset with `--surfaces rest,mcp`; a surface that is off is absent
from the discovery document and 404s, so "off" and "broken" stay
distinguishable.

Two implementations, not one, answer some of these. `rust/` serves REST with
its own generated OpenAPI document and MCP over both transports, held to the
same corpus and the same equivalence questions:

```bash
cd rust && cargo run -- serve --vault ../conformance/vaults/demo/vault
```

```bash
cd rust && cargo run -- mcp --vault ../conformance/vaults/demo/vault --principal u:carter
```

**Stated honestly.** Every network surface is read-only: §12 defines a read
surface, and replacing or deleting needs the §11 history semantics first. The
one write is [creating](#storing-notes-images-and-files), which cannot destroy
anything, and it is off unless you ask. Binary gRPC and
gRPC-Web need HTTP/2 or a Connect-aware proxy — this process serves the JSON
codec, and the `.proto` is there so clients can be generated. The GraphQL
executor is hand-written and covers queries, variables, aliases, fragments,
`@skip`/`@include` and introspection, not interfaces, unions or
subscriptions, none of which this schema uses; the SDL is the contract, so
another implementation can serve it with a full library. There are no
subscriptions or webhooks anywhere, because a read-only gatekeeper over a
store with no change feed has nothing to push.

Against an object store, the only change is the transport:

```bash
node ts/bin/basalt.mjs check --bucket my-vault --flavor r2 --endpoint https://ACCOUNT.r2.cloudflarestorage.com
```

## Storing notes, images and files

A note, an image, a PDF or any other file goes in as a **new object**: it gets
an id, a sidecar entry if it cannot carry frontmatter (§6.1), and the indexes
are refreshed, so it is linkable (`![[Assets/photo.png]]`) and under the same
access control as everything else the moment it lands. Its text is searchable
wherever §8.8 allows that: only for nodes `everyone` may read.

From the command line, as the operator who holds the vault's credentials:

```bash
node ts/bin/basalt.mjs add ~/Pictures/photo.png ~/Documents/survey.pdf Idea.md --vault path/to/vault
```

Notes go to `Notes/` and everything else to `Assets/` unless you say
`--to Folder/`; `--as Notes/Name.md` names the exact path of a single file,
`-` reads stdin, and `--title` / `--alt` fill in the note's title or the
asset's sidecar. `--principal u:someone` evaluates that principal's
`create_child` right instead of acting as the operator. Buckets and git
repositories work the same way: swap `--vault` for `--bucket` or `--git`.

On the publish site (`serve`, or a static `export`), a note is GitHub-flavoured
Markdown plus Obsidian's syntax:

- `![[photo.png]]` shows an image.
- `![[survey.pdf]]` shows a PDF in the browser's own viewer;
  `![[survey.pdf#page=3]]` opens it at page 3.
- `![[Other note]]` transcludes a note, one level deep.
- `$…$` and `$$…$$` are TeX math, rendered on the server by KaTeX to
  MathML, which browsers draw natively: no script, stylesheet or web font.
- ` ```mermaid ` blocks are drawn in the browser by Mermaid, loaded only on
  pages that have one. Mermaid's browser bundle is vendored; update it with
  `node scripts/vendor-mermaid.mjs [version]`.

Raw HTML in a note is shown as text, never run.

For an agent, the same operation is a tool on the stdio MCP server, off by
default:

```bash
node ts/bin/basalt.mjs mcp --vault path/to/vault --principal u:carter --writable
```

That adds `basalt_store` (`path`, plus `text` for anything UTF-8 or `base64`
for an image or binary, and optional `title` / `alt`). It is checked against
the principal's ACL exactly as a read is, and it hands back a `link` to paste
into a note. `--writable` requires `--principal`, and is never offered over
`/mcp`.

**Which agent, on which account.** With several Claude or Copilot accounts
writing to one vault, the server cannot see which one is on the other end of
the pipe, but each account's MCP config launches its own process, so that is
where you say:

```bash
node ts/bin/basalt.mjs mcp --vault path/to/vault --principal u:carter --writable \
  --agent claude-code --account work
```

Every object it creates is then stamped, in a note's frontmatter or (for an
image or file) its entry sidecar:

```yaml
basalt:
  id: 01jbq7xb9f2mt7vq4ny8cd3kae
  created_by:
    principal: u:carter
    agent: claude-code
    account: work
    caller: arn:aws:iam::123456789012:user/carter
    client:
      name: claude-code
      version: 2.1.0
    at: 2026-11-08T14:31:00Z
```

`principal`, `agent` and `account` are what you declared; `client` is what the
connecting program called itself and is unverified, so it sits apart. None of
it is an argument of `basalt_store`, and a `created_by` a model types into a
note is replaced, so a model cannot name its own account. `--agent` and
`--account` take short labels (`work`, `copilot:acme`), not emails or tokens;
an email address is refused. Without them a write is still stamped with the
principal and the time. `basalt add` takes the same two flags and stamps when
given them, as whatever you typed. The stamp is provenance, not audit: it
is in a file, and whoever can edit the file can edit it.

`caller` is the part nobody types. On AWS S3 the process asks STS
`GetCallerIdentity` at startup, with the same credentials the writes are
signed with, and records the ARN it gets back, so a vault that several people
write to with their own IAM users or SSO roles says whose credentials made
each object, whatever `--principal` they launched with. `basalt add` against
an AWS bucket records it too, even without `--agent` or `--account`. It
cannot tell apart people who share one profile, and it is left out on MinIO,
R2 and a local folder, which have nothing to ask. A role session named after
an email address (IAM Identity Center does this) is written as a hash of the
address, so `…/AWSReservedSSO_Editor_0123abcd/alice@example.com` is stamped
`…/AWSReservedSSO_Editor_0123abcd/sha256:ff8d9819fc0e12bf` and the address
itself never lands in a note. The ARN does carry the AWS account
number. If the lookup fails, the process says so on stderr and writes without
a caller rather than refusing to start.

**What it will not do.** It never overwrites, never deletes, and refuses a path
that is taken or that collides under §2.2 with one that is, so a mistaken
store cannot destroy a note. It refuses a note that is not UTF-8, any object
over 25 MiB, and an inline `basalt.acl` in a new note unless the writer also
holds `write_acl` (otherwise `create_child` would be a way to grant yourself
anything). Non-notes cannot sit in the vault root. Replace and delete wait on
§11; the rules are [PROTOCOL §12.7](https://github.com/CarterCole/basalt/blob/main/protocol/PROTOCOL.md).

All three implementations create objects and run the same corpus cases for it
(`conformance/cases/store/creation.yaml`): the path rules, collisions, ACL
checks, identity, and the `created_by` stamp. `basalt add` is in all three;
`basalt mcp --writable` is in `ts/` and `rust/` (`python/` has no MCP server).
In Rust:

```bash
cd rust && cargo run -- add ~/Pictures/photo.png --vault path/to/vault
```

```bash
cd rust && cargo run -- mcp --vault path/to/vault --principal u:carter --writable --agent claude-code --account work
```

Tested against the filesystem, in memory and a local MinIO (create-only puts
and the conditional sidecar update); not against real AWS S3 or R2.

## Keeping a vault in git

Any command takes `--git DIR` in place of `--vault DIR`: the vault root inside
a git working tree, at the top of the repository or in a subfolder of a bigger
one. It is still a folder. Reads come from disk, so an edit made in Obsidian
shows at once, and nothing about the files changes.

What git adds is history. Every write is committed, one commit per logical
write: a stored note with its sidecar and refreshed indexes, a reindex, a
mint.

- **Your identity, your config.** Commits use your git identity (user.name /
  user.email), with your hooks and signing settings. Trailers record who was
  behind the write: `Basalt-Principal`, `Basalt-Agent`, `Basalt-Account`,
  `Basalt-Client`.
- **Only what basalt wrote.** The commit holds exactly the files basalt
  wrote. Anything you have staged or are halfway through editing stays as it
  was.
- **No empty commits.** A reindex that changes nothing makes no commit. On
  every store, an index that differs only in `generated` is no longer
  rewritten (§13.2 excludes that field from comparison).
- **Real modification times.** A file's mtime is the time of the last commit
  that touched it, so "recent" still means something on a fresh clone.
- **Ignored files stay out of history.** Files `.gitignore` excludes are
  written to disk but not committed.

Add `--remote origin` to sync:

```bash
node ts/bin/basalt.mjs mcp --git ~/notes --remote origin --writable --principal u:carter --agent claude-code --account laptop
```

With a remote, the store pulls when it opens and before each write, and
pushes after each commit. It fast-forwards when it can and merges when two
clones have diverged.

- **Index-only conflicts settle themselves.** A merge that conflicts only in
  `index/` keeps this side's indexes, rebuilds them over the merged content
  and pushes the result.
- **Any other conflict stops the merge.** The merge is aborted, the problem
  is reported, and the write stays local until you merge by hand.
- **Nothing is ever forced.** It never force-pushes, rebases or rewrites
  history.
- **A failed sync doesn't fail the write.** Offline, or a push rejected five
  times, the write still succeeds. A warning goes to stderr and the commit
  goes out with the next push.
- **It never prompts.** It uses the ssh keys or credential helper git already
  has, and gives up on a fetch or push after 60 seconds.
- **Writers on one clone take turns.** A lock file in the git dir
  (`basalt-write.lock`) lets an MCP server and a `basalt add` beside it share
  the clone. A lock left by a process that has died is broken safely.

Two clones writing through one remote, say a laptop and a server, is the case
this is built for. One choice is yours: whether `index/` is tracked.
Tracked, which is the default, a fresh clone is ready to serve and the Pages
workflow works as is. Listed in `.gitignore`, history holds content only and
each clone builds its own indexes: run `basalt index --write --git DIR` after
cloning.

**Pushing copies the whole vault to the remote.** `audience: private` is
enforced by basalt's server, not by GitHub, so a vault pushed to a public
repository is public whatever `basalt.yaml` says. Keep private and gated
vaults in private repositories.

Stated honestly:

- A long-running `serve` or `mcp` pulls only when it writes. Notes pushed
  from another clone show up at its next write or restart.
- All three implementations have it, with the same flags (`--git DIR`,
  `--remote NAME`), the same lock file and the same commit trailers, so a
  TypeScript `basalt mcp` and a Rust or Python `basalt add` can share one
  clone.
- `npm test`, `cargo test` and `pytest` cover it with temporary repositories
  and bare remotes on disk, with your global git config shut out, including
  two clones racing through one remote. No real GitHub push is tested.

## Folders to and from GitHub gists

A gist is a small, flat set of text files that GitHub hosts. Basalt moves a
folder of a vault into one and back, in any of the three implementations, with
the same flags. Examples use the TypeScript CLI; the `basalt` command that the
Rust and Python packages install takes the same words.

```bash
# What would be sent, and nothing sent
node ts/bin/basalt.mjs gist export Projects/Basalt/ --vault ~/notes --dry-run
# A new secret gist
node ts/bin/basalt.mjs gist export Projects/Basalt/ --vault ~/notes
# Later: write the changes into the same gist
node ts/bin/basalt.mjs gist export Projects/Basalt/ --vault ~/notes --update 2c9f0a7e51d84b6a9e3f1c0d7b5a4e82
# Bring a gist into a vault, as new notes under Imported/
node ts/bin/basalt.mjs gist import https://gist.github.com/you/2c9f0a7e51d84b6a9e3f1c0d7b5a4e82 --vault ~/notes --to Imported/
```

`--vault DIR` can be `--git DIR` or `--bucket NAME` as everywhere else: the
folder comes from, or goes to, whichever store the vault is in.

**Export** reads the folder and writes its text files to a gist.

- **Names are flat.** A gist has no folders, so a file's path inside the
  folder becomes one file name, with `%` written `%25` and `/` written `%2F`:
  `Notes/Ideas/A.md` is the file `Notes%2FIdeas%2FA.md`. Import undoes it.
  A gist someone made by hand, with plain names, imports as it looks.
- **Text only.** A gist holds non-empty text, so a PNG, any file that is not
  UTF-8, and an empty file are left out. They are listed by name, never
  dropped silently. More than 300 files is refused (the API shows no more);
  export a smaller folder.
- **Secret is not private.** A new gist is *secret* by default: unlisted, but
  readable by anyone who has its URL. `--public` lists it for everyone. Either
  way it copies the notes off your machine, and `audience: private` in
  `basalt.yaml` is enforced by basalt's server, not by GitHub. `--dry-run`
  shows what would go first.
- **`--principal ID`** sends only what that principal may read, and counts
  (without naming) what it withheld. Without it you act as the operator, as
  `basalt add` does.
- **`--update ID`** adds new files and rewrites changed ones, and sends
  nothing if nothing changed. It leaves files that are in the gist but not in
  the folder, and says so; `--prune` removes them. A gist keeps its revisions
  either way. `--public` is for new gists only, because GitHub does not let a
  gist change sides. `--description TEXT` sets the gist's description.

**Import** stores every file of a gist as a new object, as `basalt add`
does (§12.7): each gets an id, notes keep their text and take a fresh id, and
a file whose path is taken is refused and reported, never replaced. The rest
still go in. The default folder is `Gists/<id>/`. On a git store the whole
import is one commit. Reading a public or secret gist needs no token.

**The token.** Writing needs a GitHub token with the `gist` scope, read from
`GITHUB_TOKEN`, then `GH_TOKEN`, then `gh auth token` (a login in the GitHub
CLI's keyring). There is no `--token` flag, which would put it in shell
history and `ps`. It is sent only to the API host, over https, and never to
the host that serves raw files. `--api-url URL` (or `GITHUB_API_URL`) points at
GitHub Enterprise.

### A whole vault in a gist

`gist export --whole` sends every key of the vault, not just a folder's
content, so the result is itself a vault, and `--gist ID` opens it like
`--vault`, `--git` or `--bucket`:

```bash
node ts/bin/basalt.mjs gist export --whole --vault ~/notes
node ts/bin/basalt.mjs add note.md --gist 2c9f0a7e51d84b6a9e3f1c0d7b5a4e82
node ts/bin/basalt.mjs mcp --gist 2c9f0a7e51d84b6a9e3f1c0d7b5a4e82 --principal u:carter
```

Stated honestly, a gist is a small store, not a general one:

- **Small and text.** At most 300 files, and a write of a binary or empty
  file is refused by name. Keep images in a folder, git or bucket vault.
- **One revision per batch.** A `basalt add` is one gist revision, however
  many files and indexes it writes.
- **Not atomic.** GitHub has no conditional write, so two writers at once can
  overwrite each other; the create-only guarantee is checked against a fresh
  read, not enforced by the server. For a vault written from two places, use
  `--git` with `--remote`.
- **Reads are cached for 30 seconds** (the API allows 60 reads an hour without
  a token). A long-running `serve` or `mcp` sees another writer's change after
  that, or at its next write.
- `--whole` is for the operator and refuses `--principal`: it copies ACLs,
  principals and indexes as they are.

Tested with `npm test`, `cargo test` and `pytest` against a local stand-in for
the gist API that is as strict as GitHub is known to be (no `/` in a name, no
empty file, a 401 without the token, a file cut short over a size). Not
tested against github.com itself.

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
trivially; so does a git working tree, a zip file or a Postgres large-object
table.

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

A static host also sends no headers of ours, so a file a browser would open
as a page and run is left out of the export: `.html`, `.xml` and their kin,
and any SVG that holds more than a drawing (script, links, markup from
another namespace, an editor's own metadata elements). The export names each
file it leaves out. `basalt serve` still serves them, as downloads or in a
sandbox with no script and an origin of their own.

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

Beyond L4, the interop surfaces are declared as **profiles** — `P-REST`,
`P-GRAPHQL`, `P-JSONRPC`, `P-MCP`, `P-GRPC`, `P-WEBDAV`, `P-FEEDS`, `P-RDF`,
and `P-INTEROP` for holding two or more of them equivalent. Profiles are
orthogonal to levels because they do not stack: speaking GraphQL implies
nothing about speaking WebDAV. A vault declares what it serves in
`publish.interop` — present, it is a ceiling a gatekeeper may not exceed;
absent, the vault claims nothing and the operator decides — and
[`conformance/cases/interop/`](https://github.com/CarterCole/basalt/tree/main/conformance/cases/interop/) holds the
requirements and the equivalence questions. `ts/` serves all eight profiles,
`rust/` serves `P-REST`, `P-MCP` and `P-INTEROP`, `python/` none yet.

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
