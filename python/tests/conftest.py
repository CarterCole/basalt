"""Shared fixtures: the language-neutral corpus in ``conformance/`` (§14.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from basalt import yamlio

def _find_conformance() -> Path:
    """Locate the shared corpus, in either repository layout.

    In the monorepo ``conformance/`` sits beside ``python/`` at the repository
    root. In the per-language repository it is inside a git submodule at
    ``spec/`` (a checkout of CarterCole/basalt pinned to the commit this
    release was tested against). Walk up from the package and take the first
    directory, or its ``spec/`` child, that has ``conformance/manifest.yaml``.
    """
    here = Path(__file__).resolve().parent
    for directory in (here, *here.parents):
        for candidate in (directory / "spec", directory):
            if (candidate / "conformance" / "manifest.yaml").is_file():
                return candidate / "conformance"
    raise FileNotFoundError(
        "the conformance corpus was not found: run `git submodule update --init` "
        "in a per-language checkout, or run from the monorepo"
    )


CONFORMANCE = _find_conformance()


def corpus(relative: str) -> Any:
    """Load one corpus file. Expectations live in ``conformance/``, never here."""
    return yamlio.load((CONFORMANCE / relative).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def conformance_root() -> Path:
    return CONFORMANCE


def pytest_report_header() -> str:
    manifest = corpus("manifest.yaml")
    total = sum(s.get("cases", 0) for s in manifest.get("suites", []))
    return f"basalt conformance corpus {manifest['corpus']}: {total} cases, {CONFORMANCE}"
