# Releasing Basalt to crates.io, PyPI and npm

Status (2026-11-12): **PyPI is published; crates.io and npm are waiting on
credentials.** Each registry gets one package, `basalt-vault`, holding the
library, the `basalt` command and (in Rust and TypeScript) the MCP server. Each
package has its own repository, and pushing a `vX.Y.Z` tag to that repository
publishes that version.

| Registry | Repository | State |
|---|---|---|
| PyPI | `python-basalt` | **`basalt-vault` 1.0.0 published** by the `v1.0.0` tag (a Trusted Publisher; the first run of that workflow on GitHub) |
| crates.io | `rust-basalt` | ready and tested, **not tagged**: needs a `CARGO_REGISTRY_TOKEN` secret for the first release |
| npm | `ts-basalt` | ready and tested, **not tagged**: needs an `NPM_TOKEN` secret for the first release |

The repositories were split out of this one with their history, carry the spec
as a submodule pinned to `9a11585`, and include the security hardening from
that commit (one critical and seven high audit findings, plus the YAML merge
key rule of §13.4). The audit's twelve medium findings and its low findings are
not addressed.

Verified rather than assumed, from a copy of each package laid out as its own
repository (package at the root, the spec in `spec/`):

| Check | Result |
|---|---|
| `cargo publish --dry-run -p basalt-vault` | passes; 36 files in a git checkout: library, `basalt` binary, README, LICENSE; no tests |
| `npm publish --dry-run` in `ts/` | `basalt-vault-1.0.0.tgz`, 44 files, 1.7 MB, with its own README and LICENSE |
| `uv build` + `twine check` in `python/` | both pass; wheel has LICENSE and `py.typed`, sdist leaves out tests, `spec/` and the workflow |
| Rust / TypeScript / Python suites | 145 / 373 (12 skipped) / 387 passing, at spec `9a11585` |
| The §12.7 store cases | all pass in all three |
| The three `release.yml` workflows | pass `actionlint`. Python's has run on GitHub and published; the Rust and npm ones have **not** run yet, so their first tag is their first real run |

## 1. Shape: one package and one repository per language

| Registry | Package | Repository | Holds |
|---|---|---|---|
| crates.io | `basalt-vault` | [`CarterCole/rust-basalt`](https://github.com/CarterCole/rust-basalt) | the `basalt` library and the `basalt` binary (CLI, self-check, `serve`, `mcp`) |
| PyPI | `basalt-vault` | [`CarterCole/python-basalt`](https://github.com/CarterCole/python-basalt) | the library and the `basalt` entry point |
| npm | `basalt-vault` | [`CarterCole/ts-basalt`](https://github.com/CarterCole/ts-basalt) | the library, the `basalt` bin and the MCP server |

[`CarterCole/basalt`](https://github.com/CarterCole/basalt) stays the home of
the spec (`protocol/`) and the conformance corpus (`conformance/`).

`basalt` is taken on all three registries and `basalt-protocol` on two, so
the package is `basalt-vault` everywhere. In Rust the import name stays
`basalt` (`[lib] name = "basalt"`), and the binary is `basalt` in all three.

An earlier plan shipped the conformance corpus as a fourth package
(`basalt-conformance`) and split the Rust CLI into `basalt-vault-cli`. Both
are gone:

- **The corpus is not published.** It lives once, in `CarterCole/basalt`.
  Each language repository carries it as a git submodule at `spec/`, pinned to
  a commit, so a tag records exactly which corpus the release passed. The
  published packages leave their tests and `spec/` out (`exclude = ["tests/"]`
  in Rust, `files` in npm, the wheel's package list and the sdist `exclude` in
  Python), so nobody downloads a test suite that cannot find its fixtures.
- **The CLI is in the library crate.** `cargo install basalt-vault` gets the
  `basalt` binary; `cargo add basalt-vault` gets the library. Both come from
  one crate.

Each tests directory finds the corpus by walking up from the package until a
directory, or its `spec/` child, holds `conformance/manifest.yaml`
(`ts/test/support/spec.mjs`, `rust/basalt/tests/support/mod.rs`,
`python/tests/conftest.py`). The same tests therefore run in the monorepo,
where that is the repository root, and in a language repository, where it is
`spec/`.

Each package directory (`ts/`, `python/`, `rust/`, `rust/basalt/`) holds a
copy of the root `LICENSE`, because a registry packs only what is inside the
package. The crate's page is `rust/README.md`; npm and PyPI have their own.
Links to the spec and the corpus are absolute URLs into `CarterCole/basalt`,
since no registry resolves a link that points outside the package.

`ts/bin/basalt.mjs schema proto` prints `protocol/basalt.proto`, which is part
of the spec and not of the npm package. It works from the monorepo and from a
language repository with `spec/` checked out; from an installed package it
prints where to find the file.

## 2. What the three implementations agree on

Every implementation runs the whole corpus at L0–L4. All three also create
objects (§12.7) and run `conformance/cases/store/creation.yaml`, so the
write path agrees by test rather than by intent: path rules, collisions,
ACL checks, identity at birth, and the `created_by` stamp, including the
email hashing in `caller`. All three keep a vault in git (`--git DIR
--remote NAME`), with the same lock file and commit trailers, so they can
share one clone. All three also move folders to and from GitHub gists
(`gist export`, `gist import`, `--gist ID`) and run
`conformance/cases/gist/mapping.yaml`, so a gist one of them writes the
others read. That suite is tooling, not protocol, so it has no level.

What still differs, on purpose:

| | TypeScript | Rust | Python |
|---|---|---|---|
| Interop profiles | all | `P-REST`, `P-MCP`, `P-INTEROP` | none |
| `basalt mcp --writable` | yes | yes | no MCP server |
| Publish site, static export | yes | export only | no |
| S3 | optional dependency | `--features s3` | `s3` extra |
| GitHub gists | built in (Node's `fetch`) | `gist` feature, on by default | built in (standard library) |
| Topic search | no | no | `topics` extra |

## 3. Release order

Once, to set up (steps 1 to 3 were done on 2026-11-12; step 4 is done for PyPI
only):

1. Commit everything in this repository, so the split starts from a commit,
   and push it, so the corpus commit the submodules pin exists on GitHub.
2. For each of `rust` → `rust-basalt`, `python` → `python-basalt`,
   `ts` → `ts-basalt`, carve the directory out with its history and push it:
   `git subtree split --prefix=<dir> -b split/<dir>`, then push that branch to
   the new repository's `main`.
3. In each new repository, add the spec and commit:
   `git submodule add https://github.com/CarterCole/basalt.git spec`, with
   `shallow = true` set for it in `.gitmodules`.
4. Set up publishing credentials for each registry (below).

Then, for every release of a package:

1. Bump the version in the manifest (`rust/Cargo.toml`'s
   `[workspace.package]`, `ts/package.json`, `python/pyproject.toml`) and
   commit.
2. Tag `vX.Y.Z` on that commit and push the tag. The workflow checks the tag
   against the manifest, runs the suite, dry-runs the package, and publishes.
3. To move the corpus a package is tested against, advance the submodule
   (`git -C spec fetch && git -C spec checkout <commit>`) and commit it before
   tagging.

The three packages are independent: none depends on another, and each is
versioned by its own tags. The first release of each is `v1.0.0`.

## 4. Version policy

- **Spec version and package version are different numbers.** The spec is
  `basalt: 1` (§16) and changes only on a breaking spec change. Package
  versions are ordinary semver per implementation.
- All three start at `1.0.0`: they pass the full corpus at L0–L4 and agree
  byte for byte. The open question is whether the Rust and Python *APIs*
  are ready for that promise (see §6).

## 5. Automation

Each language repository has `.github/workflows/release.yml` (kept in this
repository at `<dir>/.github/workflows/release.yml`, so the split carries it
along). It runs on a `v*` tag and publishes only if the tag matches the
manifest and every test, including the whole conformance corpus, passes. That
agreement is the product.

| Registry | Keyless (preferred) | Fallback |
|---|---|---|
| crates.io | Trusted Publishing, through `rust-lang/crates-io-auth-action` | secret `CARGO_REGISTRY_TOKEN` |
| PyPI | a Trusted Publisher for the repository, workflow `release.yml`, environment `pypi` | secret `PYPI_API_TOKEN` |
| npm | a Trusted Publisher for the repository and workflow (needs npm 11.5.1+), with `--provenance` | secret `NPM_TOKEN` |

Setting these up happens on each registry's website and in each repository's
secrets, so it is done by hand. As far as I know, crates.io and npm want the
package to exist before a Trusted Publisher can be attached, so the first
release of those two may need the token fallback; PyPI accepts a pending
publisher for a package that does not exist yet. A tag with a prerelease part
(`v1.1.0-rc.1`) goes to npm under the `next` dist-tag, so it never becomes
what `npm install basalt-vault` fetches.

## 6. Open questions

1. **1.0.0 or 0.x?** Semver-wise, `1.0.0` commits to the public API; the
   protocol is stable, but the Rust and Python APIs are young.
2. **Default S3 in the Rust binary?** `cargo install basalt-vault` reads
   folders and git; a bucket needs `--features s3`. Defaulting it on would
   pull the AWS SDK into every library user's build.
3. **An MCP server for Python**, to close the last gap in the table above.
4. **`gist` on by default in the Rust crate?** It is, so the installed binary
   works out of the box (a native client: `ureq` and rustls, 17 extra crates
   on Unix and `ring`, which needs a C compiler to build). A library user
   opts out with `default-features = false`. Making it opt-in like `s3` would
   keep the library lean and cost `cargo install` users a flag.
5. **What stays in `CarterCole/basalt`.** It still holds `rust/`, `ts/` and
   `python/`, and the demo site's workflow builds from `ts/`. Once the
   language repositories are the source of truth, those directories should
   leave the monorepo, and the site should install `basalt-vault` from npm or
   check out `ts-basalt`. Until then the same code lives in two places.
