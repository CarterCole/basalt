"""Topic search, the optional layer in :mod:`basalt.topics`.

Not protocol: nothing here is in the conformance corpus, and the model's exact
scores are not asserted, only what a user would notice: that it finds notes the
keyword index cannot, and above all that it never learns from a note its
requester may not read, which is §8.8 and §12.5 applied to a model.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basalt import topics
from basalt.cli import main
from basalt.indexer import EPOCH
from basalt.topics import (
    NoSuchNote,
    TooFewNotes,
    TopicSearch,
    TopicsUnavailable,
    default_num_topics,
)
from basalt.transport.local import LocalTransport
from basalt.vault import Vault

from .conftest import CONFORMANCE
from .test_vault import build

needs_gensim = pytest.mark.skipif(topics.models is None, reason="needs the 'topics' extra")

DEMO = CONFORMANCE / "vaults" / "demo" / "vault"

GEOLOGY = {
    "Geology/Basalt.md": "Basalt is a volcanic rock formed when lava cools quickly at the "
    "surface. It is rich in iron and magnesium and is the most common rock of the ocean floor.",
    "Geology/Columns.md": "Columnar jointing makes hexagonal columns as a thick lava flow cools "
    "and contracts. The cracks spread through the basalt and meet at angles of about one "
    "hundred and twenty degrees.",
    "Geology/Causeway.md": "The causeway on the coast is made of thousands of hexagonal basalt "
    "columns, left by lava flows that cooled and cracked long ago.",
    "Geology/Granite.md": "Granite is an intrusive igneous rock. Magma cooled slowly "
    "underground, so the crystals grew large, unlike the fine grains of lava that cooled "
    "quickly at the surface.",
}
BAKING = {
    "Kitchen/Sourdough.md": "Sourdough bread needs flour, water, salt and a fermented starter. "
    "Knead the dough, let it rise overnight and bake it in a hot oven until the crust is dark.",
    "Kitchen/Baguette.md": "A baguette dough rises with yeast, flour and water, then bakes in a "
    "steam oven until the crust turns crisp and golden.",
    "Kitchen/Focaccia.md": "Focaccia is a flat bread. Dimple the risen dough, add olive oil and "
    "salt, and bake it in a hot oven until golden.",
    "Kitchen/Rolls.md": "Soft rolls use milk and butter in the dough. Let the dough rise twice "
    "before it goes into the oven.",
}
CODE = {
    "Code/Rust.md": "Rust ownership and borrowing let the compiler check memory safety "
    "without a garbage collector. Lifetimes describe how long a reference is valid.",
    "Code/Python.md": "Python generators and iterators stream data lazily, so a program "
    "never holds the whole file in memory at once.",
    "Code/Go.md": "Go channels and goroutines make concurrent programs simple. The compiler "
    "is fast and a single binary is easy to deploy.",
    "Code/Types.md": "A type system catches mistakes before a program runs. The compiler "
    "checks that every reference and every value is used the way its type allows.",
}
SECRET = {
    "Secret/Plan.md": "The acquisition term sheet values the zebracorn startup. Keep the "
    "valuation and the acquisition price confidential until the deal closes.",
}


def _id(n: int) -> str:
    return f"01jbq1{n:020d}"


def _vault(notes: dict[str, str]) -> Vault:
    """A vault of these notes. ``Secret/`` is closed to everyone but u:carter (§8.3)."""
    objects: dict[str, str] = {
        "principals/users.yaml": (
            "users:\n"
            "  - {id: 'u:carter', status: active}\n"
            "  - {id: 'u:reader', status: active}\n"
            "  - {id: 'u:other', status: active}\n"
        ),
        "meta/acl/acl.yaml": (
            "folder:\n  dacl:\n"
            "    - {type: allow, subject: everyone, rights: [read, list, traverse, publish], "
            "flags: [oi, ci]}\n"
        ),
        "meta/acl/Secret/acl.yaml": (
            "folder:\n  protected: true\n  dacl:\n"
            "    - {type: allow, subject: 'u:carter', rights: [read, list, traverse], "
            "flags: [oi, ci]}\n"
        ),
    }
    for n, (path, text) in enumerate(notes.items(), start=1):
        title = path.rsplit("/", 1)[-1].removesuffix(".md")
        objects[f"content/{path}"] = (
            f"---\nbasalt:\n  id: {_id(n)}\ntitle: {title}\n---\n# {title}\n\n{text}\n"
        )
    vault = build(objects)
    vault.reindex(generated=EPOCH)
    return vault


@pytest.fixture
def vault() -> Vault:
    return _vault({**GEOLOGY, **BAKING, **CODE, **SECRET})


def paths(hits: list[dict]) -> list[str]:
    return [h["path"] for h in hits]


# --------------------------------------------------------------- finding


@needs_gensim
def test_finds_notes_by_topic_that_share_no_word_with_the_query(vault: Vault) -> None:
    """The reason to have it: "volcanic stone" is about all four geology notes.

    Only one of them contains "volcanic" and none contains "stone", so the
    keyword index cannot return the other three.
    """
    keyword = vault.search("u:reader", "volcanic stone")["hits"]
    assert [h["path"] for h in keyword] == ["Geology/Basalt.md"]

    hits = TopicSearch(vault).find("u:reader", "volcanic stone")
    assert set(paths(hits)[:3]) <= set(GEOLOGY)
    assert len(set(paths(hits)) & set(GEOLOGY)) >= 3
    assert not set(paths(hits)) & (set(BAKING) | set(CODE))


@needs_gensim
def test_a_query_in_another_subject_finds_that_subject(vault: Vault) -> None:
    hits = TopicSearch(vault).find("u:reader", "loaf of bread in the oven")
    assert set(paths(hits)[:3]) <= set(BAKING)


@needs_gensim
def test_related_finds_the_neighbours_of_a_note_and_not_the_note(vault: Vault) -> None:
    hits = TopicSearch(vault).related("u:reader", "Kitchen/Sourdough.md")
    assert "Kitchen/Sourdough.md" not in paths(hits)
    assert set(paths(hits)[:3]) <= set(BAKING)


@needs_gensim
def test_a_query_of_words_no_note_uses_finds_nothing(vault: Vault) -> None:
    assert TopicSearch(vault).find("u:reader", "qqqqzzzz xxxxyyyy") == []


@needs_gensim
def test_results_are_ranked_and_reproducible(vault: Vault) -> None:
    first = TopicSearch(vault).find("u:reader", "hexagonal lava columns")
    second = TopicSearch(vault).find("u:reader", "hexagonal lava columns")
    assert first == second, "two fits over the same notes ranked differently"
    scores = [h["score"] for h in first]
    assert scores == sorted(scores, reverse=True)
    assert all(0 < s <= 1.00001 for s in scores)


@needs_gensim
def test_equal_scores_are_ordered_by_path() -> None:
    """Two notes with the same words tie exactly; the path, not insertion order, settles it."""
    twin = "Bread rises in the oven. The dough needs flour, water and salt."
    vault = _vault({**GEOLOGY, **BAKING, **CODE, "Twin/B.md": twin, "Twin/A.md": twin})
    hits = TopicSearch(vault).find("u:reader", "bread dough oven")
    twins = [h for h in hits if h["path"].startswith("Twin/")]
    assert [h["path"] for h in twins] == ["Twin/A.md", "Twin/B.md"]
    assert twins[0]["score"] == twins[1]["score"]


# ------------------------------------------------- §8.8 / §12.5 for a model


@needs_gensim
def test_the_model_never_learns_from_a_note_the_principal_cannot_read(vault: Vault) -> None:
    """§8.8 — the leak a post-hoc filter would miss.

    A model fitted over the whole vault and filtered at query time still has
    "zebracorn" in its vocabulary and the Secret note in its loadings. Asking
    for it by name is the obvious probe; the vocabulary is the thorough one.
    """
    search = TopicSearch(vault)
    seen_by_reader = search._model("u:reader")
    assert not any(n.path.startswith("Secret/") for n in seen_by_reader.notes)
    assert "zebracorn" not in seen_by_reader.dictionary.token2id
    assert search.find("u:reader", "zebracorn acquisition valuation") == []

    seen_by_owner = search._model("u:carter")
    assert "Secret/Plan.md" in {n.path for n in seen_by_owner.notes}
    assert "zebracorn" in seen_by_owner.dictionary.token2id
    # The note is found by its own words. Outliers share a few words with
    # whatever cluster is nearest, so it is first rather than alone.
    assert paths(search.find("u:carter", "zebracorn acquisition valuation"))[0] == "Secret/Plan.md"


@needs_gensim
def test_a_warm_cache_does_not_carry_one_principals_visibility_to_another(vault: Vault) -> None:
    """§12.5 — "the single most likely place for a conforming-looking implementation to leak".

    Ask as the owner first, so the model that can see the Secret note is the
    one in the cache, then as the reader.
    """
    search = TopicSearch(vault)
    assert "Secret/Plan.md" in paths(search.find("u:carter", "acquisition price"))
    assert "Secret/Plan.md" not in paths(search.find("u:reader", "acquisition price"))


@needs_gensim
def test_models_are_shared_by_what_can_be_read_not_by_who_asks(
    vault: Vault, monkeypatch: pytest.MonkeyPatch
) -> None:
    fits: list[str] = []
    real = topics._fit
    monkeypatch.setattr(
        topics, "_fit", lambda principal, *a: fits.append(principal) or real(principal, *a)
    )
    search = TopicSearch(vault)
    search.find("u:reader", "lava")
    search.find("u:reader", "bread")
    assert fits == ["u:reader"], "a second query refitted"

    search.find("u:other", "lava")  # reads exactly what u:reader reads
    assert fits == ["u:reader"], "an identical visibility set refitted"

    search.find("u:carter", "lava")  # reads one more note
    assert fits == ["u:reader", "u:carter"]


@needs_gensim
def test_related_treats_an_unreadable_note_exactly_like_a_missing_one(vault: Vault) -> None:
    """§12.3 — a different answer for "forbidden" would confirm the path exists."""
    search = TopicSearch(vault)
    with pytest.raises(NoSuchNote) as hidden:
        search.related("u:reader", "Secret/Plan.md")
    with pytest.raises(NoSuchNote) as missing:
        search.related("u:reader", "Secret/Nothing.md")
    assert type(hidden.value) is type(missing.value)
    assert str(hidden.value).replace("Plan", "X") == str(missing.value).replace("Nothing", "X")
    assert paths(search.related("u:carter", "Secret/Plan.md", min_score=0)) != []


@needs_gensim
def test_the_cache_is_bounded(vault: Vault, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(topics, "MAX_MODELS", 1)
    search = TopicSearch(vault)
    search.find("u:reader", "lava")
    search.find("u:carter", "lava")
    assert len(search._models) == 1


# ------------------------------------------------------------- the edges


@needs_gensim
def test_too_few_readable_notes_is_an_error_not_an_empty_answer() -> None:
    small = _vault({"A.md": "lava cools into rock", "B.md": "bread rises in the oven"})
    with pytest.raises(TooFewNotes, match="can read 2"):
        TopicSearch(small).find("u:reader", "lava")


@needs_gensim
def test_a_vault_with_nothing_readable_by_anonymous_says_so() -> None:
    """The gated minimal vault: anonymous reads nothing, so there is nothing to model."""
    gated = Vault(LocalTransport(CONFORMANCE / "vaults" / "minimal" / "vault"))
    gated.load()
    with pytest.raises(TooFewNotes, match="anonymous can read 0"):
        TopicSearch(gated).find("anonymous", "columns")


def test_the_number_of_topics_scales_with_the_vault() -> None:
    assert default_num_topics(1) == 2  # never fewer than two dimensions
    assert default_num_topics(12) == 3
    assert default_num_topics(400) == 20
    assert default_num_topics(10**7) == topics.MAX_TOPICS


def test_without_gensim_it_says_how_to_get_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(topics, "models", None)
    small = _vault({**GEOLOGY, **BAKING})
    with pytest.raises(TopicsUnavailable, match=r"basalt-vault\[topics\]"):
        TopicSearch(small).find("u:reader", "lava")


# ----------------------------------------------------------------- the CLI


@needs_gensim
def test_cli_find_ranks_the_public_notes_and_hides_the_draft(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["find", "volcanic rock cooling", "--vault", str(DEMO)]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].endswith("Geology/Basalt.md")
    assert "Drafts/" not in out

    # u:editor may read the draft, and it is the best match for its own words.
    assert main(["find", "publish export", "--vault", str(DEMO), "--principal", "u:editor"]) == 0
    assert "Drafts/Unfinished Thoughts.md" in capsys.readouterr().out
    assert main(["find", "publish export", "--vault", str(DEMO)]) == 0
    assert "Drafts/" not in capsys.readouterr().out


@needs_gensim
def test_cli_find_like_takes_a_note_and_refuses_one_the_principal_cannot_read(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["find", "--like", "Geology/Basalt.md", "--vault", str(DEMO)]) == 0
    out = capsys.readouterr().out
    assert "Geology/Columnar Jointing.md" in out
    assert "Geology/Basalt.md" not in out

    draft = "Drafts/Unfinished Thoughts.md"
    assert main(["find", "--like", draft, "--vault", str(DEMO)]) == 1
    assert "no readable note" in capsys.readouterr().err


def test_cli_find_wants_a_query_or_a_note_but_not_both(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["find", "--vault", str(DEMO)]) == 1
    assert main(["find", "lava", "--like", "Geology/Basalt.md", "--vault", str(DEMO)]) == 1
    assert "not both" in capsys.readouterr().err


def test_cli_find_without_gensim_names_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(topics, "models", None)
    assert main(["find", "lava", "--vault", str(DEMO)]) == 1
    assert "basalt-vault[topics]" in capsys.readouterr().err


def test_find_never_writes_into_the_vault(tmp_path: Path) -> None:
    """Derived on demand: a topic model is not an index (§0), so nothing lands in ``index/``."""
    import shutil

    copy = tmp_path / "vault"
    shutil.copytree(DEMO, copy)
    before = sorted(p.relative_to(copy).as_posix() for p in copy.rglob("*") if p.is_file())
    main(["find", "volcanic rock", "--vault", str(copy)])
    after = sorted(p.relative_to(copy).as_posix() for p in copy.rglob("*") if p.is_file())
    assert before == after
