"""The Basalt conformance corpus, as a package.

The corpus is language-neutral YAML plus whole vaults with expected index
output (PROTOCOL §14.2). This package exists so a *published* implementation
can reach it: the corpus lives at the repository root, outside every package
directory, and a wheel built from ``python/`` would otherwise contain zero
fixture files.
"""

from pathlib import Path

__all__ = ["corpus_dir", "case", "vault", "expected"]

_HERE = Path(__file__).resolve().parent


def corpus_dir() -> Path:
    """The corpus root.

    Resolves two ways on purpose. Installed, the fixtures sit in ``assets/``
    inside the package. In the repository they do not — the corpus is the
    repo's own ``conformance/`` directory, and reading it directly is what
    makes a fixture fix break every implementation's tests the same minute,
    rather than when someone remembers to re-sync.
    """
    embedded = _HERE / "assets"
    if embedded.is_dir():
        return embedded
    return (_HERE / "../../../../conformance").resolve()


def case(relative: str) -> Path:
    """A path within the corpus, e.g. ``cases/acl/evaluation.yaml``."""
    return corpus_dir() / relative


def vault(name: str) -> Path:
    """A conformance vault, e.g. ``minimal``."""
    return corpus_dir() / "vaults" / name / "vault"


def expected(name: str) -> Path:
    """A vault's committed expected index output."""
    return corpus_dir() / "vaults" / name / "expected"
