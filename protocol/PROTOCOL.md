# The Basalt Protocol, v1

**A portable, self-describing knowledge vault that lives in any key-value
object store, with real per-object access control and fully derived indexes.**

Obsidian is volcanic glass; basalt is the volcanic rock that cools into
hexagonal columns. This protocol gives a published knowledge vault the same
property H3 gives the globe: one canonical, computable name for every piece,
and a structure any implementation can reconstruct without asking a server.

A vault is **a flat set of key→blob pairs and nothing else**. No database, no
directory inodes, no server-side state. The storage layer is required to do
five things (§1). Everything above that — virtual folders, stable object
identity, NTFS-style inherited permissions, the link graph, search — is
defined here as *content and derived artifacts inside the same key space*.
Point an implementation at a local folder, an S3 bucket, MinIO, or Cloudflare
R2 and it behaves identically, because the vault carries its own structure.

Two consequences are load-bearing and worth stating up front:

1. **Content is the only source of truth.** Every index in §10 is derived.
   Delete every index and a conforming implementation rebuilds all of them
   from content alone, byte for byte.
2. **Index generation is deterministic.** Two independent implementations,
   given the same content, MUST emit byte-identical index objects (§13).
   This is what makes conformance (§14) mechanically checkable rather than a
   matter of opinion.

This document is the normative spec. The reference implementation is the
TypeScript package in `ts/`; `rust/` and `python/` implement the same
protocol and are held to the same fixture corpus in `conformance/`.

Normative keywords MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119.

---

## 1. The substrate

A **transport** is an adapter over a flat key-value blob namespace. It MUST
provide exactly these five operations and MAY provide the optional ones:

| Operation | Signature | Semantics |
|---|---|---|
| `get` | `key → bytes \| NOT_FOUND` | Whole-object read. |
| `put` | `key, bytes, meta? → stat` | Create or replace, atomic per key. |
| `delete` | `key → void` | Remove one key. Idempotent; see §1.2. |
| `list` | `prefix, delimiter? → {keys, prefixes, cursor?}` | Enumerate. Paginated. |
| `stat` | `key → {size, etag, mtime} \| NOT_FOUND` | Metadata without the body. |

Optional capabilities, each declared in the manifest (§3.1):

| Capability | Meaning |
|---|---|
| `presign` | Mint a time-limited direct read URL for a key (§12.4). |
| `conditional_put` | Honor if-match/if-none-match, enabling optimistic concurrency (§11.3). |
| `range_get` | Serve byte ranges. |
| `versioning` | Retain superseded object versions (§11). |
| `batch_delete` | Delete many keys in one call. |

**Consistency.** The protocol assumes only read-after-write for a single key
and eventual consistency for `list`. An implementation MUST NOT depend on
`list` reflecting a `put` that has just returned. This is why index freshness
is established by digest (§10.6) and never by listing order or timestamps.

### 1.2 Delete tells you nothing

`delete` returns **no information about whether the key existed**. An
implementation MUST NOT report prior existence from `delete`, and callers MUST
NOT branch on anything it returns.

This is forced by the stores the protocol targets. S3's `DeleteObject` is
idempotent and answers `204 No Content` whether or not the key was there;
MinIO and R2 match it. Reporting existence would require a `stat` before every
`delete` — an extra round trip on the hot path, and still racy, since the key
can appear or vanish between the two calls. A local filesystem *can* answer
cheaply, which is exactly the trap: an implementation developed only against a
filesystem will expose a boolean that silently becomes wrong the day the vault
moves to a bucket.

To learn whether a key exists, call `stat` and accept that the answer is
already stale.

**What the transport is explicitly not allowed to be asked for:** server-side
ACLs, directories, atomic multi-key transactions, sorted range scans beyond
prefix matching, per-object metadata beyond the three `stat` fields, or any
report of prior existence from `delete` (§1.2). Those
are the capabilities S3-like stores disagree about, so the protocol builds
over the intersection, not the union. A local filesystem adapter satisfies
all five operations trivially; so does a zip file, a Postgres large-object
table, or an IPFS pin set.

### 1.1 Keys

A key is an **opaque, non-empty UTF-8 string**. The protocol attaches meaning
to the `/` character by convention only (§2); no transport is asked to treat
it structurally.

A conforming implementation MUST reject, on write, any key that:

- is empty, or longer than 1024 bytes when UTF-8 encoded;
- contains a NUL, or any C0/C1 control character;
- contains a path segment equal to `.` or `..`;
- contains an empty segment (`//`), or begins or ends with `/`;
- is not in Unicode Normalization Form C (NFC);
- differs from an existing key only by Unicode case or normalization form
  (§2.2 — the collision rule).

Keys are **case-sensitive and compared byte-wise** after NFC normalization.
Implementations MUST NOT lowercase keys, because S3 does not, and a vault
that relied on case folding would break when moved to a case-sensitive store.

---

## 2. Paths and virtual folders

### 2.1 Paths

A **path** is a key within the `content/` subtree with that prefix removed.
`content/Notes/Ideas/Hexes.md` has path `Notes/Ideas/Hexes.md`. Paths use `/`
as separator, have no leading or trailing separator, and name exactly one
object.

A **folder** is any proper prefix of a path ending at a separator. Folders are
**virtual**: they are not stored, they are *implied* by the paths that exist
beneath them. `Notes/Ideas/` is a folder because `Notes/Ideas/Hexes.md`
exists. Deleting the last object under a folder makes the folder cease to
exist. Implementations MUST NOT write empty "directory marker" objects.

A folder MAY carry a **folder record** (§6) giving it a title, display order
and its own ACL. The record's presence does not create the folder, and its
absence does not prevent one — records are decoration over implied structure.
This is the one place where the protocol deliberately diverges from a real
filesystem: there is no such thing as an empty folder.

### 2.2 The collision rule

Two distinct keys that are equal after NFC normalization and Unicode
case-folding **collide**. A vault MUST NOT contain colliding keys.

This rule exists because a vault must survive round-tripping through a
case-insensitive store (macOS HFS+/APFS default, Windows NTFS, some S3
gateways) without silent data loss. `Notes/Hexes.md` and `Notes/hexes.md` are
distinct keys in S3 and the same file on a Mac. A conforming implementation
MUST detect collisions during indexing and report them as a vault integrity
error (§10.8), not resolve them silently.

**Folder-case divergence** is a separate, weaker condition: two keys whose
*folder* segments fold together while the keys themselves do not, such as
`content/Notes/a.md` and `content/notes/b.md`. These do not collide — both
files survive a round trip — but the two folders merge into one on a
case-insensitive store, so `b.md` moves and every path-shaped link to it
(§9.2 steps 1-3) breaks. Implementations MUST report divergence as an
integrity **warning** (`FOLDER_CASE_DIVERGENCE`) and MUST NOT rewrite either
key to resolve it, since picking a winner would move a file the author did
not ask to move.

### 2.3 Reserved prefixes

The top-level keys `basalt.yaml`, and the prefixes `content/`, `meta/`,
`index/`, `principals/`, and `history/` are reserved by this spec. An
implementation MUST NOT store anything but what §3 describes under them, and
MUST ignore unknown keys under reserved prefixes rather than erroring, so that
a v1 reader can operate on a v1.1 vault.

Any other top-level prefix is available to applications and MUST be preserved
untouched by implementations that rewrite indexes.

---

## 3. The vault layout

```
basalt.yaml                       the manifest (§3.1)
content/…                         the vault proper: md, assets, anything
meta/
  folders/<folder>/folder.yaml    folder record (§6)
  acl/<folder>/acl.yaml           security descriptors for a folder + its
                                  direct entries (§8.6)
principals/
  users.yaml                      user principals (§7.1)
  groups.yaml                     group principals, nestable (§7.2)
  roles.yaml                      named rights masks (§7.4)
index/
  nodes.json                      id ↔ path, hash, size, kind (§10.1)
  links.json                      the edge list (§10.2)
  backlinks.json                  reverse adjacency (§10.3)
  tags.json                       tag → nodes (§10.4)
  search.json                     term postings (§10.5)
  digest.json                     merkle root over content (§10.6)
history/<node-id>/<version>.json  optional version records (§11)
```

Everything under `content/` is the vault as a human would keep it. Point
Obsidian, a text editor, `rg`, or `git` at that one subtree and it works,
because Basalt adds nothing to it but frontmatter keys (§4.2). All protocol
machinery lives in sibling trees. That separation is deliberate: it is what
makes a vault openable by tools that have never heard of this spec.

**Division of format by authorship**, applied without exception:

- **YAML** for anything a human writes or hand-edits: the manifest, folder
  records, ACLs, principals, roles.
- **JSON** for anything a machine generates: every object under `index/` and
  `history/`, serialized canonically (§13) so it is byte-reproducible and
  diffable.
- **Markdown with YAML frontmatter** for content.

An implementation MUST NOT hand-edit index JSON or generate YAML under
`index/`. The rule means a reviewer always knows which files a human may have
touched and which are safe to delete and regenerate.

### 3.1 The manifest

`basalt.yaml` is the only key whose location is fixed. It MUST exist.

```yaml
basalt: 1                      # spec major version, integer, required
vault:
  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P   # ULID, immutable, required
  title: Carter's Notes
  created: 2026-10-18T14:31:00Z
  default_locale: en
transport:
  capabilities: [presign, conditional_put, versioning]
publish:
  audience: gated               # public | gated | private  (§12.2)
  home: Notes/Start Here.md     # path of the entry node
  theme: basalt-default
  interop: [P-REST, P-MCP]      # interop profiles served  (§17, INTEROP §10)
index:
  stale_policy: rebuild         # rebuild | serve-stale | refuse  (§10.6)
security:
  bypass_traverse: false        # §8.5
  anonymous_principal: anonymous
  deny_unresolved: true         # unresolvable principal ⇒ deny  (§8.4)
  redact_titles: true           # §9.5
```

Requiring the manifest at a **fixed key** makes it a transport sanity check as
well as a version marker. A misconfigured transport — wrong bucket, wrong
prefix, wrong S3 addressing style — characteristically makes `list` return an
empty result rather than an error, which is indistinguishable from an empty
vault. Because `get` of a fixed key fails loudly under the same
misconfiguration, a reader that insists on the manifest before trusting a
listing cannot mistake a broken connection for an empty vault.

`basalt` is the **spec major version**. A reader MUST refuse a vault whose
`basalt` value it does not implement, and MUST tolerate unknown keys at any
level within a version it does implement. `vault.id` is immutable for the
life of the vault; copying a vault to a new bucket preserves it, forking a
vault MUST mint a new one.

---

## 4. Object identity

### 4.1 Node ids

Every content object has a **node id**: a ULID, lowercase Crockford base32,
26 characters. Node ids are opaque; implementations MUST NOT parse meaning out
of them beyond the ULID timestamp prefix, and MUST NOT assume they sort in
creation order across machines.

A node id is **immutable for the life of the object** and survives rename,
move, retitle, and content rewrite. It is what links (§9) and ACLs (§8) point
at, so that moving a note breaks nothing.

### 4.2 Where identity is stored — dual addressing

Basalt addresses every object **twice**, and this is the central structural
decision of the protocol:

- **By path**, which is the key itself — human-meaningful, mutable, and what
  makes the content tree browsable by unaware tools.
- **By node id**, which is recorded *inside the object* and is stable.

For a markdown object the id lives in frontmatter:

```yaml
---
basalt:
  id: 01jbq7x8z4n3vyk9m2t5hrwc6p
title: Hexagons all the way down
tags: [geometry, h3]
---
```

For an object that cannot carry frontmatter — an image, a PDF, a binary — the
id lives in a **sidecar** at `meta/folders/<folder>/entries.yaml`, keyed by
the entry's basename (§6.1).

The reason identity goes in the content rather than only in an index: **the
mapping must survive losing every index.** A rename performed by a tool that
knows nothing about Basalt — `mv`, a drag in Finder, an S3 copy — moves the
frontmatter with the bytes, so the id follows the content automatically and
the next index rebuild records the new path against the same id. Had the id
lived only in `index/nodes.json`, that rename would be indistinguishable from
a delete plus a create, and every inbound link and every ACL entry attached to
the node would be lost.

### 4.3 Minting and repair

An object encountered under `content/` with no discoverable id is **unbound**.
On the next write-capable index pass an implementation MUST mint a ULID for
each unbound object and persist it (frontmatter for markdown, sidecar
otherwise). A read-only implementation MUST surface unbound objects in the
index with `id: null` and MUST NOT invent ephemeral ids, because a transient
id would attach ACLs and links to something that ceases to exist.

If two objects carry the **same** id — the usual cause being a file copied
with its frontmatter intact — the object whose path sorts first under §13.3
keeps the id, every other claimant is treated as unbound and re-minted, and
the collision MUST be reported as an integrity warning (§10.8). Resolution is
deterministic so that two implementations repairing the same damaged vault
reach the same result.

---

## 5. Content objects

### 5.1 Kinds

| Kind | Detection | Indexed for links | Indexed for search |
|---|---|---|---|
| `note` | extension `.md`, `.markdown` | yes | yes |
| `data` | extension `.yaml`, `.yml`, `.json` | yes (§9.4) | yes |
| `asset` | any other recognized media type | no | filename only |
| `opaque` | unrecognized | no | filename only |

Kind is a function of the key alone. An implementation MUST NOT sniff bytes
to decide kind, so that kind is computable from a `list` result without
fetching anything.

### 5.2 Notes

A note is UTF-8 markdown. It MAY open with a YAML frontmatter block: a line
containing exactly `---`, the YAML body, and a closing line of exactly `---`.
The opening delimiter MUST be the first line, with no leading blank line and
no byte-order mark before it.

Reserved frontmatter keys, all under the `basalt` mapping so that user keys
can never collide with protocol keys:

| Key | Type | Meaning |
|---|---|---|
| `basalt.id` | ULID | node id (§4.2) |
| `basalt.acl` | mapping | inline security descriptor, overrides `meta/acl` (§8.6) |
| `basalt.publish` | bool | exclude from publication when `false` |
| `basalt.aliases` | list of string | alternate names for link resolution (§9.3) |
| `basalt.created`, `basalt.updated` | RFC 3339 | authored timestamps |

Conventional non-reserved keys — `title`, `tags`, `description` — are read if
present but belong to the user. `title` falls back to the first H1, then to
the filename stem. `tags` accepts a list or a comma-separated scalar, and its
values merge with inline `#tags` from the body (§9.6).

Frontmatter that fails to parse as YAML MUST NOT fail the whole index pass.
The implementation records a per-node parse error (§10.8), treats the note as
having no frontmatter, and indexes its body normally. One malformed file must
never cost a vault its index.

### 5.3 Data objects

`.json`, `.yaml` and `.yml` objects under `content/` are content, not
configuration. They are indexed for search and scanned for links (§9.4). This
is how a vault holds structured records — a dataset, a bibliography, an export
from another system — as first-class linkable nodes rather than as opaque
attachments.

---

## 6. Folder records

A folder record decorates an implied folder (§2.1). It lives at
`meta/folders/<folder>/folder.yaml`, is entirely optional, and MUST NOT be
required for the folder to exist or be traversable.

```yaml
basalt:
  id: 01jbq7xa1c8kd4re6wz0ps2n7m   # folders get node ids too
title: Field Notes
order: [Start Here.md, Ideas, Archive]   # explicit display order
sort: manual                             # manual | name | created | updated
collapsed: true
publish: true
```

`order` lists direct entry names; entries not named fall after the listed
ones in `sort` order. Names referring to entries that do not exist are
ignored, not errors — a folder record outliving a deleted file is normal.

Folders carry node ids because an ACL attached to a folder must survive the
folder being renamed, exactly as for notes (§4.2). A folder's id lives in its
record; a folder with no record has no id and inherits permissions purely
positionally.

### 6.1 Entry sidecars

`meta/folders/<folder>/entries.yaml` carries per-entry metadata for objects
that cannot hold frontmatter:

```yaml
entries:
  diagram.png:
    id: 01jbq7xb9f2mt7vq4ny8cd3kae
    title: Column jointing, annotated
    alt: Hexagonal basalt columns seen from above
  survey-2026.pdf:
    id: 01jbq7xc5h6pw1zb8ke2rm4fdx
```

Keys are entry basenames, not paths. An entry listed here that no longer
exists MUST be pruned on the next write-capable index pass.

---

## 7. Principals

Principals are the subjects of access decisions. Every principal has an id
that is unique within the vault and stable; ids are the strings that appear in
ACEs (§8.2).

### 7.1 Users

`principals/users.yaml`:

```yaml
users:
  - id: u:carter
    display: Carter Cole
    email: carter@example.com
    status: active            # active | suspended
  - id: u:reviewer
    display: Outside Reviewer
    status: active
    expires: 2026-12-31T00:00:00Z
```

A suspended or expired user MUST be treated as resolving to **no groups and
no allows**, while still matching ACEs that name it directly for Deny. Denies
outlive suspension on purpose: suspending an account must never widen access.

The protocol does not define authentication. How a request becomes a
principal id is the gatekeeper's concern (§12.1); the vault stores only
identity and rights.

### 7.2 Groups

`principals/groups.yaml`:

```yaml
groups:
  - id: g:editors
    display: Editors
    members: [u:carter]
  - id: g:staff
    display: All Staff
    members: [g:editors, u:reviewer]    # groups nest
```

Membership is transitive: `u:carter` is in `g:staff` via `g:editors`.
Expansion MUST be cycle-safe — a membership cycle is an integrity error, and
the expansion MUST still terminate and yield the reachable set rather than
hanging or overflowing.

The **effective principal set** of a request is the principal, plus every
group reachable from it transitively, plus the applicable well-known
principals (§7.3). Every ACE whose subject is in that set participates in the
decision (§8.4).

### 7.3 Well-known principals

| Id | Matches |
|---|---|
| `everyone` | every request, authenticated or not |
| `anonymous` | requests carrying no identity |
| `authenticated` | any request that resolved to a real user |
| `owner` | the principal named as owner of the object being accessed |
| `system` | the implementation itself, for index maintenance (§8.8) |

These are reserved. A vault MUST NOT define a user or group with any of these
ids, and an implementation MUST reject a principals file that does.

### 7.4 Roles

A role is a named rights mask, so ACLs can say `read_write` instead of
restating a mask. `principals/roles.yaml`:

```yaml
roles:
  reader:    [read, list, traverse]
  commenter: [read, list, traverse, comment]
  editor:    [read, list, traverse, comment, write, create_child, delete_child]
  owner:     [full_control]
```

Roles are **expanded at evaluation time, never baked into stored ACEs**, so
editing a role changes every ACE that names it. Five role names — `reader`,
`commenter`, `editor`, `owner`, `auditor` — are predefined with the masks
above and MAY be overridden by the vault. An ACE naming an undefined role is
an integrity error and MUST be treated per `security.deny_unresolved`.

---

## 8. The security model

Basalt implements **NTFS-style discretionary access control**: an ordered ACL
of allow and deny entries per object, with flag-driven inheritance down the
folder tree, explicit entries overriding inherited ones, and deny-by-default
for anything no entry grants.

This is a deliberately heavier model than object-store ACLs can express — S3
has no concept of an inherited deny — and that is precisely why it lives in
protocol content and is enforced by a gatekeeper (§12) rather than delegated
to the bucket.

### 8.1 Rights

| Right | Guards |
|---|---|
| `read` | the object's bytes |
| `list` | enumerating a folder's entries |
| `traverse` | passing *through* a folder to reach a descendant (§8.5) |
| `comment` | appending annotations without altering content |
| `write` | replacing an object's content |
| `create_child` | creating entries in a folder |
| `delete` | deleting the object itself |
| `delete_child` | deleting entries in a folder |
| `read_acl` | reading the security descriptor |
| `write_acl` | modifying the DACL |
| `take_ownership` | becoming owner |
| `read_history` | reading prior versions (§11) |
| `publish` | exposing the object to the `anonymous` principal |

`full_control` is shorthand for every right above, expanded at evaluation
time. The separation of `read` from `list`, and of `delete` from
`delete_child`, is taken from NTFS because both distinctions are load-bearing:
a folder can be made traversable-but-not-enumerable, and a user can be
allowed to tidy a folder without being allowed to delete the folder itself.

`publish` is not an NTFS right and is Basalt's own. A node reachable by
`anonymous` requires `publish` **in addition to** `read`, so that "shared with
everyone who has an account" and "on the public internet" are different
decisions and no single mis-set ACE can confuse them.

### 8.2 Access control entries

```yaml
- type: allow            # allow | deny
  subject: g:editors     # user, group, role-bearing subject, or well-known
  rights: [read, write]  # explicit rights, roles, or full_control
  flags: [ci, oi]        # inheritance flags, §8.3
```

An ACE's `subject` MUST resolve to a principal (§7). `rights` MAY name roles
(§7.4), which expand in place.

### 8.3 Inheritance flags

Taken from NTFS, with the same meanings:

| Flag | Name | Effect |
|---|---|---|
| `oi` | object inherit | applies to non-folder descendants |
| `ci` | container inherit | applies to folder descendants |
| `np` | no-propagate | applies to direct children only, then stops |
| `io` | inherit-only | does not apply to the object carrying it |

An ACE with neither `oi` nor `ci` is **explicit**: it applies only to the
object that carries it. When an ACE propagates to a child it is recorded as
**inherited** there, and `np` clears both `oi` and `ci` as it propagates, so
the grant reaches children and stops.

A folder MAY set `protected: true` in its descriptor to **block inheritance**
from its ancestors — the NTFS "disable inheritance" case. Evaluation at and
below that folder considers no ancestor above it. A protected folder SHOULD
carry its own complete descriptor, since otherwise it denies everything to
everyone, which is valid but rarely intended.

### 8.4 The evaluation algorithm

To decide whether principal `p` may exercise right set `R` on object `o`:

1. **Build the subject set** `S`: `p`, its transitive groups (§7.2), the
   applicable well-known principals (§7.3), and `owner` if `p` owns `o`.
2. **Collect descriptors** from `o` up to the vault root, stopping at the
   first `protected: true`. Order them *nearest-first*: `o`'s own descriptor,
   then its parent folder's, then that folder's parent, and so on.
3. **Flatten to a candidate ACE list**, preserving that order. Within one
   descriptor, preserve the authored order of ACEs. Drop any ACE whose
   subject is not in `S`; drop inherited ACEs that do not apply to `o`'s kind
   per its flags (`oi` for non-folders, `ci` for folders); drop `io` ACEs when
   evaluating the object that carries them.
4. **Partition into four bands** and concatenate them in this order:
   explicit deny, explicit allow, inherited deny, inherited allow. Inherited
   entries from a nearer ancestor precede those from a farther one.
5. **Resolve each right in `R` independently.** Walk the banded list in
   order; the first ACE mentioning that right decides it — `deny` type denies,
   `allow` type allows. A right no ACE mentions is **denied**.
6. The request succeeds only if every right in `R` resolved to allow.

Three properties of this ordering are worth making explicit, because they are
where naive implementations go wrong:

- **Explicit beats inherited, and deny beats allow only within a band.** An
  explicit allow on a note *does* override an inherited deny from its folder.
  This is NTFS behavior and it is what makes "deny the whole tree, allow this
  one file" expressible. An implementation that globally prioritizes deny over
  allow is not conforming.
- **Rights resolve independently.** A single ACE list can allow `read` and
  deny `write` for the same subject in one pass. Decisions are per-right, and
  an implementation MUST NOT short-circuit the whole request on the first
  denied right if it needs to report which rights were denied.
- **Nearer ancestors win.** Two conflicting inherited denies are ordered by
  distance, so the closest folder's intent governs.

If a subject, role or group fails to resolve, the behavior is governed by
`security.deny_unresolved` (§3.1): when `true` (the default and the
recommended setting) the ACE is treated as a deny of all its rights; when
`false` it is dropped. The default is the safe direction — a typo in a group
name must not silently grant access.

### 8.5 Traverse

Reading `Notes/Private/Secrets.md` requires `read` on that node **and**
`traverse` on `Notes/` and `Notes/Private/`. Listing a folder requires `list`
on it and `traverse` on each ancestor.

When `security.bypass_traverse` is `true` in the manifest, the ancestor
`traverse` checks are skipped and only the leaf decision governs — the
analogue of the Windows "Bypass traverse checking" privilege. This exists
because deep vaults otherwise require `traverse` grants on every intermediate
folder, which is tedious and a common source of accidental lockout. It is
`false` by default: implementations MUST require the full chain unless the
vault opts out.

Note the interaction with §8.4 step 2: `traverse` on an ancestor is decided by
that ancestor's *own* evaluation, including its own inheritance chain. The
checks compose; they are not one flattened pass.

### 8.6 Where descriptors live

A security descriptor attaches to a folder or a node, and may be written in
either of two places:

**Per-folder ACL files**, `meta/acl/<folder>/acl.yaml`, carrying the
descriptor for the folder itself and for its direct entries:

```yaml
folder:
  owner: u:carter
  protected: false
  dacl:
    - {type: allow, subject: g:editors, rights: [editor], flags: [ci, oi]}
    - {type: allow, subject: everyone,  rights: [read, list, traverse], flags: [oi]}
entries:
  Secrets.md:
    owner: u:carter
    dacl:
      - {type: deny,  subject: everyone, rights: [read], flags: []}
      - {type: allow, subject: u:carter, rights: [full_control], flags: []}
```

**Inline in note frontmatter**, under `basalt.acl`, with the same shape as an
`entries` value. An inline descriptor **replaces** the node's entry in the
folder ACL file; the two are not merged. Merging two hand-edited sources would
make the effective ACL depend on load order, so the protocol picks one winner:
inline, because it travels with the content.

The grouping is per folder rather than per object for a practical reason:
evaluating §8.4 for a node at depth *d* requires *d* fetches rather than *2d*,
and every fetch is cacheable by folder. A vault with ten thousand notes in a
hundred folders has a hundred ACL objects.

### 8.7 Effective rights

An implementation SHOULD expose, for a given principal and object, the
computed set of allowed rights together with the ACE that decided each one.
This is the equivalent of the Windows "Effective Access" tab, and without it
an inherited-deny misconfiguration in a deep tree is very hard to diagnose.
The gatekeeper surfaces it at `GET /api/v1/effective` (§12.3).

### 8.8 The system principal

Index maintenance reads every object regardless of ACL, because the link
graph must be complete to be correct. Index passes therefore run as `system`,
which bypasses evaluation entirely.

This creates the protocol's sharpest hazard: **the indexes know everything**.
`index/links.json` contains edges into private notes, and `search.json` would
contain their text. The mitigations are normative, not advisory:

- `search.json` MUST NOT contain text extracted from a node unless that node
  grants `read` to `everyone` or the index is itself access-controlled.
- A gatekeeper MUST filter every index-derived response through §8.4 for the
  requesting principal before returning it (§12.5).
- Index objects MUST NOT be served by `presign` (§12.4) or placed behind a
  public CDN path.

An implementation that publishes a vault by copying `index/` to a public
bucket alongside public content is **not conforming**, because that leaks the
private half of the graph. §12.6 defines the safe export.

---

## 9. Links

The link graph is the reason a vault is more than a folder. Basalt specifies
link extraction and resolution exactly, because "which note does `[[Hexes]]`
mean" must not be answered differently by two implementations of the same
vault.

### 9.1 Recognized forms

| Form | Kind | Notes |
|---|---|---|
| `[[Target]]` | `wiki` | wikilink by name or path |
| `[[Target\|Alias]]` | `wiki` | display text differs from target |
| `[[Target#Heading]]` | `wiki` | anchor into a heading |
| `[[Target#^blockid]]` | `wiki` | anchor to a block |
| `![[Target]]` | `embed` | transclusion; renders target inline |
| `[text](Target.md)` | `md` | markdown link, relative or rooted |
| `[text](https://…)` | `external` | any absolute URL with a scheme |
| `#tag`, `#nested/tag` | `tag` | §9.6 |

Extraction MUST ignore link-like text inside fenced code blocks (``` or ~~~),
inline code spans, math blocks, and HTML comments. A `[[…]]` inside a code
fence is a code sample, not an edge, and indexing it would pollute the graph
of any vault that documents this protocol — including this one.

An empty target, a target consisting only of whitespace, or an unterminated
`[[` MUST be skipped silently rather than recorded as unresolved.

### 9.2 The resolution algorithm

Given raw target `t` (anchor and alias already stripped) appearing in a note
at path `p`, resolve in this order and stop at the first hit:

1. **Rooted path.** If `t` starts with `/`, interpret the remainder as a path
   from the vault root. Try it, then with each extension in
   `[.md, .markdown]` appended.
2. **Exact relative path.** Resolve `t` against the folder containing `p`,
   normalizing `.` and `..`. Try as written, then with each extension.
3. **Exact vault-root path.** Interpret `t` as a path from the vault root.
   Try as written, then with each extension.
4. **Alias match.** Any node declaring `t` in `basalt.aliases` (§5.2),
   compared case-insensitively after NFC.
5. **Unique basename.** Any node whose filename stem *or* full basename
   equals `t`, compared case-insensitively after NFC. Both spellings are
   matched because `[[Hexes]]` and `![[diagram.png]]` are both ordinary: a
   note is normally referenced without its extension and an asset normally
   with one, and a resolver that indexed only the stem would leave every
   image embed dangling.
6. **Unresolved.** Record the edge with `target: null` and `raw: t`.

If step 4 or 5 matches more than one node the link is **ambiguous**. The
implementation MUST pick the candidate whose path sorts first under §13.3,
MUST set `ambiguous: true` on the edge, and MUST list every candidate in the
edge record. Ambiguity is reported, never hidden: a deterministic tiebreak
keeps two implementations in agreement, and the flag lets an author fix the
real problem.

Resolution is **case-insensitive at steps 4 and 5, case-sensitive at steps
1–3.** Path-shaped targets mean exactly what they say; name-shaped targets are
forgiving, because that is how people type them.

### 9.3 Anchors

An anchor after `#` is carried on the edge but does not affect which node
resolves. `#^id` denotes a block id; anything else is a heading reference,
slugified for comparison by lowercasing, NFC-normalizing, replacing runs of
whitespace with `-`, and stripping characters outside `[a-z0-9-_]`. A heading
anchor that matches no heading in the target MUST NOT make the edge
unresolved — the node resolved; only the fragment did not. The edge records
`anchor_resolved: false`.

### 9.4 Links in data objects

In `.json`, `.yaml` and `.yml` content objects (§5.3), any **string value**
whose entire content matches a wikilink form is an edge, and so is any string
under a key named `link`, `links`, `ref`, `refs`, `href`, or `url` that parses
as a path or URL. Keys are never scanned, only values. Scanning keys would
turn a dataset's column names into edges.

### 9.5 Redaction

An edge whose target the requesting principal cannot `read` MUST NOT be
removed from a response — removing it would make the graph silently wrong, and
a reader could not tell a redacted link from a dangling one. Instead the edge
is returned with `target` replaced by `redacted`, and with its title omitted
when `security.redact_titles` is `true` (the default).

When `redact_titles` is `false`, a redacted edge keeps its target's title so
that readers see *that* something exists without reading it. That is a real
use case — a public changelog referring to internal tickets — but it is opt-in
because titles leak: "Acquisition of X, draft terms" discloses the thing it
names. The default protects the title.

### 9.6 Tags

Tags come from frontmatter `tags` and from inline `#tag` tokens in the body,
merged into one set per node. An inline tag matches `#` followed by one or
more segments of `[\p{L}\p{N}_-]+` separated by `/`; it is not a tag if
preceded by a word character (so `C#` and a URL fragment are safe) or if it
consists only of digits (so `#1` is not a tag).

`#nested/tag` implies membership in `#nested`. Tag comparison is
case-insensitive after NFC, and the index records the first-seen casing as
the display form.

---

## 10. Indexes

Every index object shares an envelope:

```json
{
  "basalt": 1,
  "kind": "nodes",
  "vault": "01JBQ7X8Z4N3VYK9M2T5HRWC6P",
  "generated": "2026-10-18T14:31:00Z",
  "source_digest": "sha256:9f2b…",
  "entries": []
}
```

`source_digest` is the merkle root (§10.6) of the content tree the index was
built from. It is how a reader decides, in **one** `get`, whether an index can
be trusted — not by comparing timestamps, which §1 forbids relying on.

`generated` MUST NOT participate in the digest or in equality comparison
between implementations (§13.2), since two runs at different times over
identical content must still produce comparable output.

### 10.1 `index/nodes.json`

One entry per content object:

```json
{"id":"01jbq7x8z4n3vyk9m2t5hrwc6p","path":"Notes/Hexes.md","kind":"note",
 "title":"Hexagons all the way down","size":4096,"etag":"\"d41d8c…\"",
 "content_hash":"sha256:1a2b…","tags":["geometry","h3"],
 "headings":[{"level":1,"text":"Hexagons all the way down","slug":"hexagons-all-the-way-down"}],
 "aliases":[],"publish":true,"owner":"u:carter","errors":[]}
```

`content_hash` is over the raw bytes. It, not `etag`, is authoritative:
etags differ between S3 implementations for multipart uploads and are useless
for cross-store comparison, so the protocol keeps both and trusts the hash.

### 10.2 `index/links.json`

One entry per edge, in document order within a source node, source nodes
ordered by path (§13.3):

```json
{"from":"01jbq7x8z4n3vyk9m2t5hrwc6p","to":"01jbq7xa1c8kd4re6wz0ps2n7m",
 "kind":"wiki","raw":"Columns","alias":null,"anchor":"jointing",
 "anchor_resolved":true,"ambiguous":false,"candidates":[],
 "line":42,"col":7}
```

An unresolved edge has `to: null` and keeps `raw`. An external edge has
`to: null`, `kind: "external"`, and `raw` holding the URL.

### 10.3 `index/backlinks.json`

Reverse adjacency, derived wholly from §10.2 and stored because computing it
on demand means reading the entire edge list for every page view:

```json
{"01jbq7xa1c8kd4re6wz0ps2n7m": ["01jbq7x8z4n3vyk9m2t5hrwc6p"]}
```

Target ids sort ascending. An implementation MUST be able to regenerate this
from `links.json` alone, and the conformance suite checks that the stored file
equals the recomputation.

### 10.4 `index/tags.json`

Tag display form → sorted node ids, plus the implied-parent closure from
§9.6, so querying `#nested` finds nodes tagged only `#nested/tag`.

### 10.5 `index/search.json`

A term → postings map, subject without exception to the leak rule in §8.8:

```json
{"terms":{"hexagon":[{"node":"01jbq…","tf":3}]},
 "stopwords":"basalt-en-v1","stemmer":"none"}
```

Tokenization MUST be declared and reproducible: Unicode word boundaries,
lowercased, NFC, stopwords from the named list. `stemmer: none` is the only
value v1 requires; an implementation MAY offer others but MUST record which
was used, because a posting list is meaningless without knowing what produced
it. Implementations differing only in `stemmer` are both conforming and their
`search.json` files are not expected to match.

### 10.6 `index/digest.json` and staleness

```json
{"basalt":1,"kind":"digest","vault":"01JBQ…","root":"sha256:9f2b…",
 "count":1284,"tree":{"Notes/":"sha256:4c1d…","Notes/Hexes.md":"sha256:1a2b…"}}
```

The root is computed over `content/` only:

1. For each content key, take `sha256(path_bytes || 0x00 || content_hash)`.
2. Sort those leaf hashes bytewise ascending.
3. Fold them: `root = sha256(concat(sorted_leaves))`.
4. The empty content tree has root `sha256("")`.

Sorting the hashes rather than the paths makes the root independent of
traversal order, so a store whose `list` is unordered (§1) cannot change the
result. Per-folder subtree hashes are recorded so an incremental pass can skip
unchanged folders.

An index whose `source_digest` differs from the current digest is **stale**.
Behavior is set by `index.stale_policy` (§3.1): `rebuild` regenerates before
answering, `serve-stale` answers from it and marks the response stale,
`refuse` returns an error. A gatekeeper MUST signal staleness in its response
(§12.3) under every policy, so a client is never silently served old data.

### 10.7 Writing indexes

A write pass MUST refuse to replace a non-empty stored index with an empty
one unless explicitly forced. Indexes are derived and rebuildable (§0), so
this cannot lose content — but a vault whose indexes have gone empty appears
empty to every reader until someone notices, and the usual cause is not an
emptied vault but a transport pointed at the wrong place (§3.1). The same
reasoning as §11.3: on a knowledge vault, silent destruction is worse than a
refusal.

Implementations SHOULD report the refusal with both counts, since "0 nodes
found, 1284 previously indexed" names the problem precisely.

### 10.8 Integrity reporting

Index passes collect, rather than throw on, these conditions: key collisions
(§2.2), duplicate node ids (§4.3), unparseable frontmatter (§5.2), membership
cycles (§7.2), unresolvable ACE subjects (§8.4), ambiguous links (§9.2), and
orphaned sidecar entries (§6.1). They are written to
`index/integrity.json` with the same envelope and a severity per entry
(`error` | `warning`). A vault with errors is still servable; refusing to
serve a vault because one file has bad frontmatter would be the wrong
trade for a publishing system.

---

## 11. History

History is optional (conformance level L5, §14.1). When present, a version
record lives at `history/<node-id>/<version>.json`:

```json
{"basalt":1,"kind":"version","node":"01jbq…","version":"01jbq7xd2k…",
 "path":"Notes/Hexes.md","content_hash":"sha256:1a2b…",
 "blob":"history/01jbq…/blobs/1a2b….md","author":"u:carter",
 "timestamp":"2026-10-18T14:31:00Z","op":"update","parent":"01jbq7xc…"}
```

Versions are ULIDs, so they sort chronologically within a node. `op` is one of
`create`, `update`, `rename`, `delete`, `acl`. A `rename` records both paths
and no new blob; an `acl` op records the descriptor before and after, because
"who could read this last month" is a question auditors actually ask.

### 11.1 Blob storage

Version blobs are content-addressed under `history/<node-id>/blobs/<hash><ext>`.
Identical content stored twice occupies one blob. A `delete` op retains the
final blob, so deletion is recoverable until history is pruned.

### 11.2 Pruning

An implementation MAY prune history and MUST record the pruning as a version
record with `op: prune` and a `retained_from` timestamp, so a gap in history
is visible rather than looking like a node that never changed.

### 11.3 Concurrency

With the `conditional_put` capability (§1), writes SHOULD be conditional on
the etag the writer read, and a failed condition MUST surface as a conflict
rather than being retried blindly — last-write-wins on a knowledge vault
silently destroys work. Without the capability, an implementation MUST
document that concurrent writes may be lost, and SHOULD serialize writes
through a single process.

---

## 12. The gatekeeper

A **gatekeeper** is an HTTP service that holds the only credentials to the
store and enforces §8 on every read. It is the component that makes
NTFS-style permissions real: the bucket itself stays private and never faces
the reader.

### 12.1 Identity

How a request acquires a principal id is out of scope — session cookie, OIDC,
signed token, mTLS, a reverse proxy header. The gatekeeper MUST reduce every
request to exactly one principal id or to `anonymous`, and MUST NOT let a
client assert its own principal id directly.

### 12.2 Audience

`publish.audience` (§3.1) sets the vault-wide ceiling:

| Audience | Meaning |
|---|---|
| `public` | `anonymous` may be granted rights by ACL |
| `gated` | every request must authenticate; `anonymous` is denied everything |
| `private` | only explicitly listed users; `everyone` grants are ignored |

The ceiling applies **before** §8.4 and can only narrow, never widen, what the
ACL allows. It exists so that an entire vault can be taken private in one
edit without auditing every ACE.

### 12.3 Read surface

| Route | Returns |
|---|---|
| `GET /api/v1/node/<path>` | content plus metadata, if `read` |
| `GET /api/v1/raw/<path>` | bytes only, if `read` |
| `GET /api/v1/list/<folder>` | direct entries, filtered to those with `list` |
| `GET /api/v1/links/<path>` | out-edges and backlinks, redacted per §9.5 |
| `GET /api/v1/search?q=` | postings filtered to readable nodes |
| `GET /api/v1/tree` | the navigable tree, pruned to what is visible |
| `GET /api/v1/effective?path=&principal=` | effective rights, if `read_acl` |
| `GET /api/v1/manifest` | the public subset of the manifest |

Every response carries `X-Basalt-Index-State: fresh | stale | rebuilt` (§10.6)
and `X-Basalt-Vault: <vault id>`.

A denial MUST distinguish two cases, and getting this wrong is an information
leak: if the principal lacks `list`/`traverse` such that it cannot know the
object exists, return **404**; if it may know the object exists but lacks
`read`, return **403**. A 403 on a path the requester was not allowed to
discover confirms that path exists.

### 12.4 Delivery

Two modes for `raw`:

- **Proxy**: the gatekeeper streams the bytes. Always correct, costs
  bandwidth through the service.
- **Redirect**: with the `presign` capability, mint a short-lived URL and
  302 to it. The TTL SHOULD be under 300 seconds, the URL MUST be bound to
  the single key, and it MUST NOT be reused across principals or cached in a
  shared cache, because a presigned URL is a bearer token that outlives the
  ACL check that produced it.

Index objects, ACL files, principals files, and anything under `meta/`,
`index/`, `principals/` or `history/` MUST NEVER be presigned or proxied raw
to a non-`system` principal (§8.8).

### 12.5 Filtering derived data

Index-derived responses — links, backlinks, search, tree, tags — MUST be
filtered through §8.4 for the requesting principal before being returned,
never after being cached. A cache key for any of these MUST include the
principal's effective subject set (§8.4 step 1), or the cache will serve one
user's visibility to another. The reference implementation hashes the sorted
subject set into the cache key; this is the single most likely place for a
conforming-looking implementation to leak, and §14 tests it directly.

### 12.6 Static export

A vault MAY be exported to a public static site. The export MUST include only
nodes granting both `read` and `publish` to `anonymous` under §8.4, and MUST
regenerate every index from that filtered subset rather than copying the
vault's indexes (§8.8). Links to excluded nodes are redacted per §9.5 at
export time, and `search.json` is rebuilt over public text only.

An export is therefore a complete, smaller vault — it carries its own
manifest and its own digest, and is itself servable by a gatekeeper. "Export"
and "publish a subset" are the same operation.

---

## 13. Canonical serialization

Determinism across implementations (§0) requires byte-level rules.

### 13.1 JSON

- UTF-8, no BOM, LF endings, exactly one trailing newline.
- Object keys sorted by §13.3 ordering.
- Two-space indentation; one key or element per line; no trailing whitespace.
- Integers bare; non-integers MUST NOT appear in index objects (no floats
  anywhere, which sidesteps every float-formatting disagreement).
- Non-ASCII characters emitted literally, not `\u`-escaped. Escape only what
  JSON requires plus U+2028 and U+2029.
- Empty arrays and objects as `[]` and `{}`.

### 13.2 Fields excluded from comparison

`generated` (§10) and the `etag` field of §10.1 are excluded when comparing
two implementations' output, since both legitimately differ. Everything else
MUST match byte for byte.

### 13.3 Ordering

All sorting is by **UTF-8 code unit sequence, bytewise ascending**, after NFC
normalization. Not locale collation, not code point order on UTF-16, not
case-insensitive. One rule, applied to paths, keys, ids, tags and terms alike.

### 13.4 YAML

Human-authored YAML (§3) is read permissively — any valid YAML 1.2 — but when
an implementation *writes* it, it MUST emit block style, two-space indents,
unquoted keys where legal, double quotes when quoting is needed, no anchors
or aliases, and preserve existing key order, appending new keys at the end.
Rewriting a human's YAML into canonical form would destroy their comments and
layout, so the rules here are about not making a mess, not about determinism.

Comments MUST be preserved when an implementation edits a YAML file it did
not author. An implementation that cannot preserve comments MUST refuse to
rewrite the file and MUST report it, rather than silently stripping them.

---

## 14. Conformance

### 14.1 Levels

An implementation declares the levels it meets. Each requires all below it.

| Level | Name | Requires |
|---|---|---|
| **L0** | Transport | the five operations, key validation (§1) |
| **L1** | Content | layout, manifest, identity, frontmatter (§2–6) |
| **L2** | Index | links, resolution, all indexes, canonical bytes (§9–10, §13) |
| **L3** | Security | principals, ACL evaluation, traverse (§7–8) |
| **L4** | Gatekeeper | HTTP surface, filtering, denial semantics (§12) |
| **L5** | History | version records, blobs, concurrency (§11) |

L0–L2 make a vault readable and indexable; a static site generator needs
exactly those. L3 adds enforcement, L4 adds serving it over HTTP, L5 adds
time travel.

Beyond L4, an implementation MAY declare **interop profiles** — the same read
surface in another protocol's vocabulary (REST/OpenAPI, GraphQL, JSON-RPC,
MCP, gRPC, WebDAV, syndication, RDF). Profiles are orthogonal to levels and
are specified in [INTEROP.md](INTEROP.md) §10; a vault declares them in
`publish.interop` (§3.1). They are profiles rather than levels because they
do not stack: speaking GraphQL implies nothing about speaking WebDAV, and
neither is a prerequisite for the other.

### 14.2 The fixture corpus

`conformance/` holds language-neutral cases. Every implementation ships a
runner that loads these and asserts; no implementation defines its own
expectations for behavior the spec covers.

```
conformance/
  manifest.yaml            case inventory, with the level each case tests
  cases/
    keys/*.yaml            key validation: input → valid | error code
    paths/*.yaml           normalization, collision detection
    frontmatter/*.yaml     parsing, id extraction, error recovery
    links/*.yaml           content → expected edge list
    acl/*.yaml             principals + descriptors + request → decision
    interop/*.yaml         per-surface requirements and the equivalence questions
  vaults/<name>/           whole vaults with expected index output
```

An ACL case names the exact ACE that decided each right, not merely the
boolean outcome. Two implementations can agree on "denied" for different
reasons, and only one of them is following §8.4; checking the deciding ACE
catches the band-ordering bug that a boolean assertion misses.

### 14.3 Self-check

A conforming implementation MUST provide a command that, given a vault,
reports: integrity (§10.8), index freshness (§10.6), whether a rebuild
reproduces the stored indexes byte for byte (§13), and the ACL evaluation of
a named principal against a named path (§8.7). This is the tool a vault owner
runs to answer "is my private note actually private", and it is required
rather than optional because without it the answer is unknowable.

---

## 15. Security considerations

**The indexes are the attack surface.** §8.8 and §12.5 exist because the link
graph and search index necessarily see everything, and every leak of a private
vault through a conforming-looking implementation will come from serving
derived data without re-filtering it. Treat `index/` as being as sensitive as
the most sensitive node in the vault, because it is.

**Presigned URLs outlive their authorization.** A URL minted under §12.4 keeps
working after the ACL changes, until it expires. Short TTLs are the only
mitigation the protocol can offer; a vault that needs revocation to be instant
MUST use proxy delivery.

**Redaction does not retract what an author published elsewhere.** §9.5 hides
a restricted node's *own* title, and §8.8 keeps its *own* text out of the
search index. Neither can do anything about a public note whose author wrote
`[[Quarterly Layoffs]]` in a sentence: that string is the public note's
content, it renders as the author typed it, and it is indexed as the public
note's text. The restricted node stays unreadable and its body stays out of
the index, but its *name* was published by whoever linked to it. An
implementation MUST NOT be understood as making a private node undiscoverable
— only unreadable. Authors who need the name itself withheld must not write it
in a public note.

**Titles and paths leak.** A path is often a sentence. §12.3's 404/403 split
and §9.5's title redaction address the obvious channels, but a tree response
pruned by `list` rights still reveals *how many* siblings were pruned unless
the implementation omits counts. Implementations SHOULD omit counts of
invisible entries.

**Deny is not revocation.** §8.4 lets an explicit allow on a node override an
inherited deny. This is intended NTFS behavior and it means a tree-wide deny
is not a guarantee about every descendant. To revoke access with certainty,
remove the allow entries, or set `protected: true` and write a descriptor that
grants nothing.

**Unresolved principals default to deny** (§8.4) because the alternative makes
a deleted group silently widen access. Implementations MUST NOT invert this
default for convenience.

**The manifest is trusted.** `security.bypass_traverse` and
`publish.audience` change enforcement globally and live in a file inside the
vault. Whoever can write `basalt.yaml` controls the security posture of the
whole vault, so `write` on it is equivalent to `write_acl` everywhere and
SHOULD be restricted accordingly.

---

## 16. Versioning this spec

The `basalt` integer in the manifest is the major version. Within a major
version, additions MUST be backward compatible: new optional keys, new
capabilities, new index kinds. A reader MUST ignore what it does not
recognize (§2.3).

---

## 17. Interoperability surfaces

§12 defines one HTTP read surface. A gatekeeper MAY additionally serve the
same vault as REST with an OpenAPI document, GraphQL, JSON-RPC, the Model
Context Protocol, gRPC/Connect, read-only WebDAV, Atom/RSS with a sitemap,
and JSON-LD/Turtle. Those surfaces are specified in
[INTEROP.md](INTEROP.md), which is normative, and declared per vault in
`publish.interop` (§3.1).

Three rules from that annex belong here, because they are statements about
§8 rather than about any protocol:

1. **One enforcement point.** Every surface MUST route through a single
   principal-scoped view of the vault, and that view MUST be the only code
   that evaluates §8.4, applies the §12.3 404/403 split, refuses the §12.4
   withheld trees and keys the §12.5 cache by subject set. Re-deriving any of
   them per protocol is a defect even when the output happens to be correct.
2. **One meaning per denial.** `not_found` MUST stay ambiguous between "no
   such object" and "you may not discover it" in every protocol's vocabulary
   (INTEROP §1.3), including in status codes, error payloads and listings.
3. **Read-only.** Every surface in the annex is a read surface. A write
   surface needs §11 history and §8's write rights settled first, so v1 has
   none, and a surface MUST refuse mutating requests rather than silently
   ignoring them.

Adding a protocol therefore adds translation, never policy. INTEROP §9 lists
the questions a conformance runner asks of every mounted surface to check
that this held.

Changes that would alter the bytes of a canonically serialized index, the
outcome of link resolution, or the result of an ACL evaluation require a major
version bump, because they would break the determinism property that §0 and
§14 rest on.

Reserved for future majors, and deliberately absent from v1: encryption at
rest with per-node keys, CRDT-based concurrent editing, mandatory access
control labels, and cross-vault transclusion. Each is a real requirement for
someone; none of them can be added to v1 without changing the meaning of
existing bytes.
