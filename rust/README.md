# basalt — Rust

A complete Rust implementation of [the Basalt Protocol v1](../protocol/PROTOCOL.md),
conformance level **L4** (Transport, Content, Index, Security, Gatekeeper).

The spec is the contract. Where a clause and an existing implementation
disagree, the clause wins; every non-obvious decision in this code carries the
section reference it comes from, so a reader can check the code against the
spec rather than against its author's memory.

```
rust/
  basalt/            the library: the protocol, with no cloud dependency
    src/
      order.rs       §13.3   NFC + UTF-8 bytewise ordering, the one comparator
      keys.rs        §1.1 §2 key validation, path algebra, collision rules
      canonical.rs   §13.1   canonical JSON: the byte-exactness core
      frontmatter.rs §5      kinds, frontmatter, error recovery, id minting
      links.rs       §9      extraction, exclusion zones, the six-step resolver
      acl.rs         §7 §8   principals, roles, the four-band evaluation
      security.rs    §8.5-6  descriptor chains and the traverse composition
      indexer.rs     §10     every index, the merkle digest, the search filter
      manifest.rs    §3.1    the manifest and the version gate
      vault.rs       §3      loading, scanning, reading, export
      gatekeeper.rs  §12     the HTTP read surface
      transport/     §1      the five operations: memory, filesystem, S3
    tests/           §14.2   the fixture corpus runners, plus the byte-exact vault
  basalt-cli/        §14.3   the `basalt` binary and its required self-check
```

## Build and test

```bash
cargo test --workspace
```

61 tests. The ones that matter most:

- `tests/conformance.rs` and `tests/acl.rs` load the language-neutral corpus in
  `../conformance/` and assert against it. No expectation for behavior the spec
  covers is written in this crate — §14.2 forbids that, and for good reason.
- `tests/expected.rs` rebuilds `conformance/vaults/minimal/vault` from content
  alone and compares all seven index objects against the bytes the TypeScript
  reference implementation committed, excluding only `generated` and `etag`
  (§13.2). **All seven reproduce byte for byte**, and six of them match the
  stored bytes exactly rather than after re-serialization. It also asserts that
  every vault in the corpus indexes deterministically across two passes, and
  that `backlinks.json` equals the recomputation from `links.json` alone, which
  §10.3 says the conformance suite checks.
  A one-off cross-check went further: both implementations were pointed at
  `conformance/vaults/demo`, which carries no committed expectations, and all
  seven outputs came out byte-identical — including a 271-term `search.json`
  and matching `etag`s.
- `tests/gatekeeper.rs::cache_is_keyed_by_subject_set` is the §12.5 leak test:
  warm the cache as a principal who can see a private note, then ask as one who
  cannot, through one gatekeeper instance. §12.5 calls this the single most
  likely place for a conforming-looking implementation to leak.

The S3 transport is behind a feature flag, so the core protocol builds with no
cloud dependency at all:

```bash
cargo test --workspace                  # no AWS SDK compiled
cargo build --features s3               # adds the S3-compatible transport
```

## The CLI

```bash
cargo run -- check --vault ../conformance/vaults/minimal/vault \
    --principal u:carter --path "Notes/Columns.md"
```

`basalt check` is the self-check §14.3 *requires* — it reports integrity,
index freshness, whether a rebuild reproduces the stored indexes byte for byte,
and the ACL evaluation of a named principal against a named path. It is the tool
a vault owner runs to answer "is my private note actually private", which is why
the spec makes it mandatory rather than optional.

Other commands: `index [--write] [--force]`, `mint`, `serve [--port N]`,
`effective --path P`, `tree`, `export --out DIR`, `digest`. `--help` for the rest.

## Implementation notes

**Why the transport trait is synchronous.** §1 asks for whole-object reads and
writes with no transactions, no streaming and no fan-out. Async buys nothing at
that boundary, so the S3 adapter owns a current-thread runtime and blocks, and
the indexer, the ACL engine and the CLI stay free of an executor. The same
reasoning applies to the gatekeeper, which is ~400 lines over `TcpListener`
rather than an async HTTP stack an order of magnitude larger than this crate.

**Why `delete` returns `()`.** §1.2. The signature *is* the enforcement: there
is no boolean to branch on, so a caller cannot come to depend on a filesystem's
ability to report prior existence and then discover the dependency the day the
vault moves to a bucket. The filesystem transport goes one step further and
holds the invariant that `delete` removes exactly what `get` would have
returned, so the two cannot disagree about what counts as an object — see
finding 8.

**Where §13.3 is nearly free.** Rust's `str` ordering is already UTF-8
bytewise, so `BTreeMap<String, Json>` *is* the key-sorting rule of §13.1 and
`compare_utf8` only has to add the NFC half. The property is still pinned by a
test (`ordering_is_utf8_bytewise`), because it is the one place a UTF-16
language silently diverges and the corpus happens not to contain an astral
character.

**Minting preserves authored YAML.** §13.4 requires comments to survive an edit
and requires an implementation that cannot preserve them to refuse the rewrite
and report it. Rather than round-tripping through a YAML emitter, `with_id`
splices one line into the existing `basalt:` mapping and leaves every other byte
alone — and genuinely refuses when the mapping is in flow style, because editing
that safely would mean restyling it.

See [FINDINGS.md](FINDINGS.md) for the places where this implementation believes
the spec or the committed corpus is wrong or genuinely ambiguous.
