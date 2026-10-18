"""The self-check command, PROTOCOL §14.3.

§14.3 makes this command a MUST rather than a nicety: "This is the tool a
vault owner runs to answer 'is my private note actually private', and it is
required rather than optional because without it the answer is unknowable."
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from basalt.cli import main

from .conftest import CONFORMANCE

MINIMAL = CONFORMANCE / "vaults" / "minimal" / "vault"


@pytest.fixture
def vault_copy(tmp_path: Path) -> Path:
    """A writable copy, so a test never writes into the corpus."""
    target = tmp_path / "vault"
    shutil.copytree(MINIMAL, target)
    return target


def test_check_reports_integrity_freshness_rebuild_and_access(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "check",
            "--vault",
            str(vault_copy),
            "--principal",
            "u:reader",
            "--path",
            "Notes/Columns.md",
        ]
    )
    out = capsys.readouterr().out

    # All four things §14.3 requires the command to report.
    assert "integrity" in out and "UNRESOLVED_LINK" in out  # §10.7
    assert "no stored index" in out  # §10.6 — nothing written yet
    assert "nothing stored to compare" in out  # §13
    assert "access" in out  # §8.7

    # The question the tool exists to answer: the private note is private.
    read_line = next(line for line in out.split("\n") if " read " in line)
    assert "deny" in read_line
    assert "g:staff" in read_line, "no deciding ACE reported"

    # The vault's only condition is a warning, so the exit status is clean.
    assert exit_code == 0


def test_check_confirms_a_byte_exact_rebuild_after_writing(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["index", "--vault", str(vault_copy), "--write"]) == 0
    capsys.readouterr()

    assert main(["check", "--vault", str(vault_copy)]) == 0
    out = capsys.readouterr().out
    assert "fresh" in out
    assert "reproduces stored indexes byte for byte" in out


def test_check_detects_a_stale_index(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["index", "--vault", str(vault_copy), "--write"])
    capsys.readouterr()
    note = vault_copy / "content" / "Notes" / "Hexes.md"
    note.write_text(note.read_text(encoding="utf-8") + "\nAppended.\n", encoding="utf-8")

    main(["check", "--vault", str(vault_copy)])
    out = capsys.readouterr().out
    assert "stale" in out
    assert "stale_policy=rebuild" in out  # §10.6 — the policy is surfaced


def test_check_exits_nonzero_on_an_integrity_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A vault with errors is still servable (§10.7), but the tool must say so.

    The condition used here is an unresolvable ACE subject rather than a key
    collision, because a collision cannot be *created* on a case-insensitive
    filesystem — which is the whole reason §2.2 exists.
    """
    root = tmp_path / "vault"
    (root / "content" / "Notes").mkdir(parents=True)
    (root / "meta" / "acl").mkdir(parents=True)
    (root / "basalt.yaml").write_text(
        "basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n", encoding="utf-8"
    )
    (root / "content" / "Notes" / "Hexes.md").write_text("# A\n", encoding="utf-8")
    (root / "meta" / "acl" / "acl.yaml").write_text(
        "folder:\n  dacl:\n"
        "    - {type: allow, subject: 'g:typo', rights: [read], flags: [oi]}\n",
        encoding="utf-8",
    )

    assert main(["check", "--vault", str(root)]) == 1
    out = capsys.readouterr().out
    assert "UNRESOLVED_SUBJECT" in out
    assert "1 error(s)" in out


def test_index_is_a_dry_run_without_write(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["index", "--vault", str(vault_copy)]) == 0
    out = capsys.readouterr().out
    assert "4 nodes, 8 edges, 7 tags" in out
    assert "dry run" in out
    # The corpus vault ships an empty index/ directory, so look for the
    # objects themselves rather than the folder (§2.1: folders are virtual).
    assert list((vault_copy / "index").glob("*.json")) == []


def test_effective_lists_every_right_with_its_decider(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "effective",
                "--vault",
                str(vault_copy),
                "--principal",
                "u:carter",
                "--path",
                "Notes/Columns.md",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    allowed = [line for line in out.split("\n") if line.startswith("allow")]
    assert len(allowed) == 13, "§8.1 lists thirteen rights, all under full_control"
    assert "take_ownership" in out
    assert all("by allow:u:carter" in line for line in allowed)


def test_tree_is_pruned_for_the_principal(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["tree", "--vault", str(vault_copy), "--principal", "u:reader"])
    out = capsys.readouterr().out
    assert "Hexes.md" in out
    assert "Columns.md" not in out


def test_digest_prints_the_root_and_freshness(
    vault_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["digest", "--vault", str(vault_copy)])
    out = capsys.readouterr().out
    assert "3aae36e38c2a4954634daefc2c9fec2960987ada999b38df5faf26579369b069" in out
    assert '"fresh": false' in out  # nothing written yet


def test_mint_is_idempotent(vault_copy: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["mint", "--vault", str(vault_copy)])
    assert "every object already carries an id" in capsys.readouterr().out


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "basalt" in capsys.readouterr().out


def test_errors_are_reported_not_traced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "--vault", str(tmp_path)]) == 1
    assert "not a Basalt vault" in capsys.readouterr().err
