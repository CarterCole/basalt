"""Shared fixtures: the language-neutral corpus in ``conformance/`` (§14.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from basalt import yamlio

#: ``conformance/`` sits beside ``python/`` at the repository root.
CONFORMANCE = Path(__file__).resolve().parents[2] / "conformance"


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
