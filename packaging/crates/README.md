# basalt-conformance

The conformance corpus for the [Basalt Protocol](https://github.com/CarterCole/basalt):
language-neutral YAML fixtures plus whole vaults with byte-exact expected
index output.

This package exists for one structural reason. The corpus lives at the
repository root, **outside every package directory**, so a published
implementation cannot reach it — `cargo package` on the implementation crate
ships zero fixture files, and the same is true of a Python wheel or an npm
tarball. Shipping the corpus as its own versioned package makes it an
ordinary dependency instead of a path that only resolves inside a git
checkout.

It also makes drift a reviewable number. "Corpus 1.0.2 → 1.0.3, three
expectations changed" is a diff someone approves, rather than a test that
goes red with no version to point at.

## What is in it

- `cases/` — key validation, path collisions, frontmatter parsing, link
  extraction and resolution, ACL evaluation, interop surfaces.
- `vaults/<name>/vault/` — complete vaults.
- `vaults/<name>/expected/` — the index output a conforming implementation
  must reproduce **byte for byte**, excluding only the fields PROTOCOL §13.2
  names.
- `manifest.yaml` — the case inventory and the conformance level each tests.

An implementation ships a runner that loads these and asserts. None defines
its own expectations for behaviour the spec covers.

## Versioning

The major version tracks the spec major (`basalt: 1`). Minor and patch
releases add cases or correct them — and corrections happen: five fixture
bugs were fixed while the reference implementation was being written, each
one found because a second implementation disagreed.
