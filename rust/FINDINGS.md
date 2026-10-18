# Findings from implementing Basalt v1 in Rust

Written against `protocol/PROTOCOL.md` as of 2026-10-18 17:07 (1241 lines,
including the new §1.2 and §10.7). Nothing in `protocol/`, `conformance/` or
`ts/` was modified.

**Headline: all seven index objects reproduce byte for byte** against the
TypeScript reference implementation. Three separate checks:

- `conformance/vaults/minimal` against the committed `expected/` — all seven
  match, and six match the stored bytes exactly rather than only after
  re-serialization (`nodes.json` carries `etag`, which §13.2 excludes).
- `conformance/vaults/demo`, which has no committed expectations, indexed by
  both implementations and compared directly: all seven **byte-identical**,
  including a 271-term `search.json` and matching `etag`s. This is the stronger
  check, since the demo vault exercises a non-empty search index, an SVG asset,
  a nested folder ACL and `publish: false` — none of which the minimal vault
  reaches.
- A synthetic vault with two malformed node ids: `integrity.json` byte-identical
  (see finding 2 for why that one is luck rather than design).

All 15 key cases, 4 collision cases, 3 folder cases, 11 frontmatter cases, 4
extraction cases, 14 resolution cases and 24 ACL cases pass.

---

## 1. §8.8's search rule is looser than the fixture it is tested by

**This is the one finding that changes observable output.**

§8.8 says:

> `search.json` MUST NOT contain text extracted from a node unless that node
> grants `read` to `everyone` or the index is itself access-controlled.

Read literally, that is a question about one ACE: does an `everyone` entry
decide `read` as allow? In `conformance/vaults/minimal`, the `Notes/` descriptor
grants `everyone` `[read, list, traverse]` with `oi`, so `Notes/Hexes.md` and
`Notes/Start Here.md` both satisfy it. Under the literal reading their body text
belongs in `search.json`.

The committed `expected/search.json` has `"terms": {}`.

It reproduces only under a stricter reading: index a node's text when an
**anonymous request would be allowed to read it on a public vault**, which
through §8.1 also requires `publish`. Nothing in the minimal vault grants
`publish`, so nothing is indexed. The reference implementation does exactly
this, and so does this one — `tests/expected.rs::search_leak_rule_requires_publish_not_only_read`
pins both halves of the argument.

§12.6 already states the strict test precisely, for the export case:

> The export MUST include only nodes granting both `read` and `publish` to
> `anonymous` under §8.4

**Suggested fix.** Make §8.8 say the same thing as §12.6:

> `search.json` MUST NOT contain text extracted from a node unless that node
> grants both `read` and `publish` to `anonymous` under §8.4, or the index is
> itself access-controlled.

Without this, two implementations reading §8.8 literally and strictly both
believe they conform and emit different `search.json` bytes — which is exactly
the class of disagreement §0 and §13 exist to prevent. The strict reading is
also the right one on the merits: `publish` is what separates "shared with
everyone who has an account" from "safe to sit in a world-readable index", and
that is §8.1's whole purpose.

**A second, smaller question inside the same rule.** The evaluation is done
against an assumed `public` audience, not against the vault's own
`publish.audience`. That matters: the minimal vault is `gated`, so using its own
audience would make the §12.2 ceiling deny `anonymous` everything and no vault
with `audience: gated` could ever have a non-empty `search.json`. That cannot be
intended — §10.5 would be dead weight for every gated vault. Using `public` is
therefore right, but the spec does not say so, and an implementer who passes the
vault's own audience gets an empty search index and no indication they are wrong.
Worth one sentence.

## 2. `integrity.json`'s `detail` strings are comparable bytes that nothing defines

§13.2 excludes exactly two fields from cross-implementation comparison:
`generated`, and the `etag` of §10.1. Everything else "MUST match byte for
byte". That includes every `detail` string in `index/integrity.json` — and the
spec defines none of them.

This is not hypothetical. As of this commit the three implementations in this
repository already disagree. For a note carrying a near-miss ULID:

```yaml
basalt:
  id: 01jbq10000000000000000000   # 25 characters; a ULID is 26
```

- `ts/` and `rust/` emit `"detail": "01jbq10000000000000000000"` (byte-identical
  to each other — verified).
- `python/` emits `"detail": "01jbq10000000000000000000: 25 characters; a ULID is 26 (§4.1)"`.

Python's wording is *better* — a sibling session changed it after a near-miss
ULID left every node unbound and every link unresolved with no hint why, and
that is a real diagnostic improvement. But under §13.2 as written it makes
`python/` non-conforming against the other two on any vault with a malformed id,
for a change that improves the product. That is a sign the rule is wrong, not
the change.

The same trap is waiting in `FRONTMATTER_PARSE`, whose detail the reference
takes from the YAML parser's own message (`err.message.split('\n')[0]`). No two
languages' YAML libraries word a syntax error the same way, so **any** vault
with malformed frontmatter produces different `integrity.json` bytes in any two
implementations. The minimal vault has no malformed frontmatter, which is the
only reason the corpus does not already catch this.

**Suggested fix — pick one:**

1. **Add `detail` to §13.2's exclusion list.** Simplest, and consistent with
   the reasoning already there: `detail` is diagnostic prose for a human, like
   `generated` is a timestamp for a human, and neither is load-bearing for
   determinism. `severity`, `code` and `path` stay comparable, which is enough
   to assert that two implementations found the same problems in the same
   places.
2. **Define every detail string in §10.8.** Preserves full byte-equality but
   freezes the wording, which means an improvement like Python's needs a major
   version bump (§16) — and §16 says changes that alter canonical index bytes
   require exactly that. This is the expensive option.

Option 1 is the right one. Option 2 makes error-message quality a
backwards-compatibility hazard.

## 3. §10.8's list of collected conditions omits unresolved links

§10.8 (§10.7 before the 17:07 revision) enumerates what an index pass collects:

> key collisions (§2.2), duplicate node ids (§4.3), unparseable frontmatter
> (§5.2), membership cycles (§7.2), unresolvable ACE subjects (§8.4), ambiguous
> links (§9.2), and orphaned sidecar entries (§6.1)

Dangling links are not in that list. But the committed
`expected/integrity.json` contains exactly one entry, and it is:

```json
{"code": "UNRESOLVED_LINK", "detail": "\"Does Not Exist\"",
 "path": "Notes/Hexes.md", "severity": "warning"}
```

So an implementation that reads §10.8 as exhaustive produces an empty
`integrity.json` and fails the byte-exact comparison, for a defensible reason.
Either add unresolved links to the list, or say the list is not exhaustive. The
first is better: the code name and severity are observable output and should be
pinned somewhere normative, since `integrity.json` is compared byte for byte
like every other index.

The same applies to `UNBOUND_NODE`, which §4.3 requires the behavior of
("MUST surface unbound objects in the index with `id: null`") without naming an
integrity code, and to `FOLDER_CASE_DIVERGENCE`, which §2.2 *does* name. The
codes that appear in `integrity.json` are part of the comparable bytes, so the
full set belongs in §10.8 as a table.

## 4. `col` in §10.2 has no declared unit, and the natural answer differs per language

§10.2's edge record carries `"line": 42, "col": 7`, and §10.2 never says what
`col` counts. The three obvious answers disagree:

| Language | What falls out naturally | Diverges for |
|---|---|---|
| JavaScript | UTF-16 code units | astral characters (emoji, rare CJK) |
| Rust | UTF-8 bytes | all non-ASCII |
| Python | Unicode scalars | nothing |

Every fixture and the whole minimal vault are ASCII, so the corpus cannot catch
this. A single `é` earlier on a line is enough to make the reference
implementation and a byte-counting implementation emit different `links.json`
bytes.

This implementation emits **1-based Unicode scalar values**, as the
language-neutral reading and the one an editor's own column display agrees with.
It matches JavaScript for all BMP content, which is why the fixtures pass either
way.

**Suggested fix.** One clause in §10.2: "`line` is 1-based and counts `\n`;
`col` is 1-based and counts Unicode scalar values." Scalars rather than bytes
because a column is a human-facing number, and the field exists so an author can
find the link in their editor.

`line` has a smaller version of the same gap: the fixtures pin it (an edge in
`Notes/Columns.md` is line 11, counting from the start of the *file* including
the frontmatter block, not from the start of the body), but §10.2 does not say
the count is file-relative. It is worth stating, because computing it
body-relative is the more natural thing to do when extraction runs on the body.

## 5. §12.6 asks for two things that pull apart

§12.6 says both of these:

> MUST regenerate every index from that filtered subset rather than copying the
> vault's indexes (§8.8)

> Links to excluded nodes are redacted per §9.5 at export time

A §9.5 redaction marker is `to: "redacted"`. An index containing one cannot be
regenerated from the exported content, because the exported content has no trace
of the excluded target — so an export carrying redaction markers in
`index/links.json` fails its own §14.3 self-check and breaks the rebuildability
§0 rests on, while §12.6's closing paragraph insists the export "is itself
servable by a gatekeeper".

This implementation follows the explicit MUST: it regenerates, so an edge to an
excluded node is simply unresolved *within the export*, which is true there.
§9.5's redaction stays where §9.5's own wording puts it — "MUST NOT be removed
from **a response**" — on the gatekeeper, which is where a redacted edge and a
dangling one are actually distinguishable.

**Suggested fix.** Reword the second sentence to scope it to responses: "A
gatekeeper serving the export redacts per §9.5 any edge whose target is absent"
— or, if baked-in markers really are intended, say so and exempt an export's
`links.json` from the rebuildability requirement explicitly, because the two
cannot both hold.

## 6. §12.6 does not say whether an export keeps `vault.id`

§3.1 says "copying a vault to a new bucket preserves it, forking a vault MUST
mint a new one", and an export is neither: it is a filtered copy whose node ids
are genuinely the same nodes. §12.6 calls the result "a complete, smaller vault"
that "carries its own manifest", without saying whether the id in it is the
source's.

It matters, because §12.3 puts `X-Basalt-Vault` on every response and §12.5
requires per-principal cache keys. A public export served alongside the private
gatekeeper under the same vault id is a plausible way for a client that caches on
that header to mix the two.

This implementation preserves the id by default and lets a caller mint a new one
(`ExportOpts::vault_id`), documented at the call site. One sentence in §12.6
would settle it.

## 7. `conformance/manifest.yaml` declares 13 resolution cases; the file has 14

`cases/links/resolution.yaml` contains 14 cases. `manifest.yaml` says
`{file: cases/links/resolution.yaml, level: L2, spec: "9.2", cases: 13}`.

All 14 pass here — the runners iterate the file, not the manifest, so nothing is
skipped. This is bookkeeping drift, not a behavior bug, but it defeats the
purpose of the inventory: a runner that *did* drive itself from the manifest
would silently skip a case. `tests/conformance.rs::corpus_inventory_matches`
hard-fails if a file holds fewer cases than declared and prints a note on a
surplus, which is how it surfaced.

## 8. §1.2 has a quieter sibling in `get` and `stat`

§1.2 closes the `delete` divergence: a filesystem can report prior existence
and a bucket cannot, so neither may. Writing the test for it turned up the same
shape in the two neighbouring operations, which §1 types as
`key → bytes | NOT_FOUND` and `key → {…} | NOT_FOUND`.

Three filesystem errors all mean "this key does not exist" on an object store,
and only the first is obvious:

| Condition | Filesystem | Object store |
|---|---|---|
| nothing at the path | `NotFound` | absent |
| the path is a directory | `IsADirectory` on read, `EPERM` (macOS) or `EISDIR` (Linux) on unlink | absent — §2.1 says folders are virtual and never stored, so no key names one |
| the path's own prefix is a file | `NotADirectory` | absent — a bucket has no opinion about the shape of a key's prefix |

A filesystem transport that surfaces any of them as an error disagrees with
every store the protocol targets, in exactly the way §1.2 describes. The fix
here holds the invariant that **`delete` removes exactly what `get` would have
returned**, decided from `metadata` rather than from `remove_file`'s error kind
— the unlink error for a directory differs per platform, so matching error
kinds is a list that silently grows a hole on the next platform.

Worth one sentence in §1, alongside §1.2: "`get` and `stat` answer NOT_FOUND,
and `delete` succeeds, for any key an object store would not have — including a
key naming a folder (§2.1) or one whose prefix is itself an object."

## 9. Smaller things

- **§1.2 is printed before §1.1.** The document goes §1 → §1.2 → §1.1 → §2.
  Purely editorial, but §1.1 is referenced constantly and the out-of-order
  heading makes it hard to find.
- **§9.2 step 5 is named "Unique basename" but handles the non-unique case.**
  The step is where ambiguity is detected and tie-broken, and the corpus
  asserts `by: unique-basename` for a case it also marks `ambiguous: true`. The
  label is fine as an identifier; the heading reads as a contradiction. "Name
  match" would be clearer.
- **§10.1's `tags` field is not specified as closed over implied parents.**
  §9.6 defines the implied-parent closure and §10.4 says `tags.json` carries it.
  The committed `nodes.json` also carries it — `Notes/Start Here.md` is tagged
  `#nav/root` inline and its `nodes.json` entry lists both `nav` and `nav/root`.
  §10.1 should say so, since it is comparable output.
- **§12.2 `private` says "only explicitly listed users; `everyone` grants are
  ignored".** Whether a *group* grant survives under `private` is unstated, as
  is `authenticated`. The corpus only tests `everyone`. A literal reading of
  "only explicitly listed users" would drop group grants too, which would be a
  surprising amount of narrowing; this implementation drops only `everyone`,
  matching the reference. Worth pinning either way.
- **§7.1 makes a suspended user's reported *decider* implementation-dependent.**
  §7.1 says a suspended user resolves to "no groups and no allows, while still
  matching ACEs that name it **directly** for Deny". Read literally, "directly"
  excludes an `everyone` deny — so `everyone` would leave the subject set along
  with the groups, and a right covered only by an `everyone` deny would come
  back `deny` by `default`. This implementation and the reference both keep
  `everyone` in the set and report `deny:everyone`. Both reach `deny` either
  way; they disagree about *which ACE said so*, and §14.2 is explicit that the
  deciding ACE is part of the assertion. The corpus's one suspended case does
  not discriminate — on `Notes/Other.md` the explicit `O3` deny naming `u:gone`
  directly is ordered first, so the `everyone` allow beside it is never
  consulted under either reading. Keeping `everyone` is better on the merits,
  since §7.1's own justification is that "suspending an account must never widen
  access" and dropping it discards a deny that applied a moment earlier; but the
  word is "directly", so `tests/acl.rs::suspended_user_decider_is_underspecified`
  pins the behavior rather than assuming it. Replacing "name it directly" with
  "name it or any well-known principal it still matches (§7.3)" would settle it.
- **§13.1 bans non-integers but §10.5's `tf` is the only numeric payload.**
  Not a problem, just an observation that the ban is cheap to honor: nothing in
  any index wants a float, so the rule costs nothing and removes a whole class
  of cross-language disagreement. It is the single best decision in §13.

## What is *not* implemented

**L5 (History, §11).** Nothing here writes `history/`, so the conformance claim
stops at L4. §11.3's `conditional_put` half *is* implemented and tested in both
the filesystem and S3 transports, since §1 lists the capability independently.

The S3 transport is compiled and type-checked but has not been run against a
live S3, MinIO or R2 endpoint — there were no credentials available in this
session. The flavor handling mirrors what `ts/src/transport/s3.mjs` documents
(R2 needs region `auto` and relaxed checksums, MinIO needs path-style
addressing), and §12.4's TTL cap and the "never presign outside `content/`" rule
are both enforced in `presign` rather than left to the caller.
