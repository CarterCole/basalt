# Releasing Basalt to crates.io, PyPI and npm

Status: **prepared, nothing published.** Renames, metadata, the corpus
packages and the dependency wiring are done and dry-run. The irreversible
step — uploading — has not been taken, and needs credentials this machine
does not have (npm is logged out; there is no PyPI configuration).

Verified rather than assumed:

| Check | Result |
|---|---|
| `cargo package --list` on the corpus crate | **0 → 46** fixture files |
| `npm pack --dry-run` on the corpus package | 46 fixture files, 24.7 kB |
| Wheel built from `packaging/pypi` | 46 fixture files |
| `cargo publish --dry-run` — corpus | passes |
| `cargo publish --dry-run` — `basalt-vault` | **fails, by design**: `no matching package named basalt-conformance found`. Cargo will not publish a crate whose dev-dependency cannot be resolved from the registry, which enforces the release order in §6 rather than leaving it to discipline. |
| Rust / TypeScript / Python suites | 77 / 146 / 216 passing |
| Rust reads the corpus via the package | yes — `basalt_conformance::corpus_dir()` |

The whole shape of this release is set by one structural fact:

> The conformance corpus lives at `conformance/`, which is **outside every
> package directory**. `cargo package --list` currently ships **zero**
> conformance files, and the same is true of a Python sdist built from
> `python/` or a tarball from `ts/`.

So a published artifact cannot see the fixtures its own tests read. Everything
below follows from fixing that.

---

## 1. Blockers found

| Problem | Detail |
|---|---|
| `basalt` is taken | **All three registries.** Not available anywhere. |
| `basalt-protocol` is taken | PyPI **and** crates.io. Free on npm only. |
| Current Python name is unpublishable | `pyproject.toml` declares `basalt-protocol` — taken. |
| Current Rust name is unpublishable | `rust/basalt/Cargo.toml` declares `basalt` — taken. |
| npm name needs an org | `@basalt/reference` requires the `basalt` scope, which does not exist yet. |
| Versions disagree | ts `0.1.0`, python `0.1.0`, rust `1.0.0`. |
| Metadata missing | No `repository` on any package; ts has no `files`/`exports`/`author`; python has no `license`/`classifiers`/`urls`. |

The GitHub repo can stay `CarterCole/basalt` — registry collisions do not
affect it.

## 2. Naming — decided

`basalt-vault` is the **only candidate free on all three registries**, and
`basalt-conformance` is likewise free on all three. Taking one name everywhere
is worth more than a marginally better name per registry: it is the string
people search, and a split identity across registries is a permanent tax.

| Registry | Package | Purpose |
|---|---|---|
| crates.io | `basalt-vault` | library |
| crates.io | `basalt-vault-cli` | the `basalt` binary |
| PyPI | `basalt-vault` | library + `basalt` entry point |
| npm | `basalt-vault` | library + `basalt` bin |
| all three | `basalt-conformance` | the corpus, shipped as data |

Unscoped on npm rather than `@basalt/reference`: it matches the other two, and
avoids depending on an org that does not exist.

**Claim all five names on all three registries before anything else.** They are
free today and cost nothing; a squatter on `basalt-conformance` after the spec
gets attention would be genuinely painful.

The manifests now declare these names, at version `1.0.0`. The Rust package is
`basalt-vault` while the *library* is still `basalt` (`[lib] name = "basalt"`),
so every `use basalt::` path in the codebase is untouched by a rename forced
on us by a registry collision.

## 3. The corpus package — the crux

`conformance/` becomes a publishable package on each registry, and each
implementation takes it as a **dev-dependency** rather than reaching up the
tree with `../../`.

This resolves both objections raised against the alternatives:

- It is reachable from a published artifact, which a sibling path is not.
- It is **versioned**, so skew is a reviewable number. "Corpus 1.0.2 → 1.0.3,
  three expectations changed" is a diff someone approves, which was the real
  argument for submodules — delivered without submodule mechanics.

### Keeping one source of truth

The corpus stays at `conformance/` in this repo. Three thin wrappers ship it:

```
conformance/              ← the single source: YAML cases + vault fixtures
packaging/
  crates/                 ← basalt-conformance crate, embeds assets/
  pypi/                   ← basalt-conformance wheel, package_data
  npm/                    ← basalt-conformance package, files[]
```

Each wrapper is near-empty: a manifest plus one accessor that returns the
corpus root (or embedded bytes). A release script copies `conformance/` into
each wrapper immediately before publishing, so the duplication exists for
seconds inside a build and never in git.

Each wrapper exposes one thing:

| Language | Accessor |
|---|---|
| Rust | `basalt_conformance::corpus_dir() -> &'static Path` (or `include_dir!`) |
| Python | `basalt_conformance.corpus_dir() -> pathlib.Path` |
| Node | `corpusDir(): string` |

### Dependency wiring, per language

**Rust** has first-class support for exactly this case:

```toml
[dev-dependencies]
basalt-conformance = { path = "../../packaging/crates", version = "1.0" }
```

Cargo uses the **path** locally — so a fixture fix still breaks Rust's tests
the same minute it breaks TypeScript's — and strips it on publish, pinning
registry **1.0** for consumers. Monorepo speed during development, explicit
pinning for everyone else.

**npm** does the same via workspaces: `"basalt-conformance": "^1.0.0"`
resolves to the local workspace package during development.

**Python is the weak one.** pip has no path/version duality. Options:
- a `[tool.uv.sources]` entry (dev) plus a normal version constraint (publish),
  which works but is uv-specific; or
- an optional `conformance` extra that pulls the released package, with the
  repo's own test run using an editable install.

This asymmetry is worth accepting rather than contorting the other two to
match the weakest packaging system.

## 4. Version policy

Proposed, and the main thing to disagree with:

- **Spec version and package version are different numbers.** The spec is
  `basalt: 1` (§16) and changes only on a breaking spec change. Package
  versions are ordinary semver per implementation.
- Every package declares which spec major it implements, in metadata
  (`keywords` / `classifiers`) and in code.
- **All four implementations start at `1.0.0`**, not `0.1.0`: they pass the
  full corpus at L0–L4, and `0.x` would signal less confidence than the
  byte-exact cross-implementation agreement actually warrants.
- `basalt-conformance` versions independently and **more often**, because a
  fixture fix is a corpus release. Its major tracks the spec major.

## 5. Metadata to add before publishing

Common to all: `repository`, `homepage`, `license = MIT`, `keywords`,
`description`, `README`.

- **ts/package.json** — add `repository`, `author`, `files` (ship `src/` and
  `bin/`, exclude `test/`), `exports`, `engines` is present. Rename to
  `basalt-vault`.
- **python/pyproject.toml** — add `license`, `authors`, `classifiers`
  (Python versions, MIT, Topic :: Text Processing), `[project.urls]`. Rename
  to `basalt-vault`.
- **rust** — add `repository`, `keywords`, `categories`, `readme` to both
  crates; set `rust-version`. Rename `basalt` → `basalt-vault` and
  `basalt-cli` → `basalt-vault-cli`, keeping the **binary** named `basalt`.

Each package keeps its own README: the registry page is the first thing a
reader sees, and the root README is written for the repo.

## 6. Release order

The corpus must exist on a registry before anything can depend on it.

1. `basalt-conformance` → crates.io, PyPI, npm.
2. Repoint all three implementations to depend on it; verify every suite
   still passes locally **and** against the published corpus.
3. `basalt-vault` → crates.io, PyPI, npm; then `basalt-vault-cli`.
4. Tag `v1.0.0`, with the spec at `basalt: 1`.

Dry-run everything first: `cargo publish --dry-run`, `twine check`,
`npm publish --dry-run`. For Rust, confirm `cargo package --list` now
**includes** the corpus assets — that number going from 0 to non-zero is the
check that this whole plan worked.

## 7. Automation

Use each registry's keyless publishing rather than long-lived tokens in
secrets:

- **PyPI** — Trusted Publishers (OIDC from GitHub Actions).
- **npm** — provenance via `npm publish --provenance` with OIDC.
- **crates.io** — Trusted Publishing.

A tag-triggered workflow that runs all three suites, then publishes in the
order above, with the corpus first. It must refuse to publish if any
implementation's byte-exact comparison fails: that property is the product.

## 8. Open questions

1. **Name**: `basalt-vault` everywhere — agreed? It is the only one free on
   all three.
2. **Start at 1.0.0 or 0.x?** Semver-wise `1.0.0` commits you to the public
   API; the protocol is stable but the Rust/Python APIs have existed for a day.
3. **Does the CLI ship on all three registries**, or pick one home (crates.io
   gives the best single-binary install) and leave the others library-only?
4. **Python corpus wiring**: uv-specific sources, or an extra?
5. **MCP server** — deferred earlier until the core worked. The core works
   now; it would be a fourth package, and the name should be claimed with the
   rest if it is coming.
