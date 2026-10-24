"""Topic search: find notes by what they are about, not by the words they use.

This is the one part of the Python package that is not the protocol. Everything
else here is held, byte for byte, to a corpus the TypeScript and Rust
implementations also pass (§13, §14.2). This cannot be: it needs gensim, which
exists only for Python (the ``topics`` extra), and a latent semantic model is a
floating-point fit whose output moves with library versions. So it is derived
on demand, never written under ``index/``, and nothing in ``conformance/``
covers it.

What it does answer to is §8.8 and §12.5. A topic model is a summary of the
text it was fitted to, and its vocabulary and loadings carry that text with
them: fitted over the whole vault and filtered afterwards, it would still have
learned from notes the requester cannot read. So the model is fitted per
requester, over only the notes that principal may read, and is cached by *which
notes those are* rather than by who asked, which is §12.5's rule for any
index-derived answer.

The model is latent semantic analysis (TF-IDF, then a truncated SVD) rather
than LDA. A vault is small and a query is a handful of words; LSA copes with
both, ranks by cosine similarity, and a note can be used as the query.

Importing this module never needs gensim; fitting a model does.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .indexer import IndexedNode, tokenize
from .order import nfc, utf8_key
from .vault import Vault

try:
    import numpy as np
    from gensim import corpora, models
except ImportError:  # the `topics` extra is optional
    np = corpora = models = None  # type: ignore[assignment]

#: Fewer notes than this and the SVD has nothing to generalise from: the
#: "topics" would be the notes themselves and every query a keyword match.
MIN_NOTES = 3

#: Cosine similarity below which a note is not reported as being on the topic.
#: Picked on gensim's 300-article Lee corpus: at 0.1 under half of what came
#: back was on topic for most queries; at 0.3 precision recovers and most of the
#: relevant notes are still there. Small vaults separate far more cleanly.
MIN_SCORE = 0.3

#: Upper bound on latent dimensions. Past a few hundred, LSA stops improving.
MAX_TOPICS = 200

#: Models kept at once. One is built per distinct set of readable notes, so a
#: long-lived caller serving many principals would otherwise grow without bound.
MAX_MODELS = 8

#: Arbitrary, but fixed: two runs over the same notes and the same library
#: versions rank identically instead of differing in the last decimal places.
_SEED = 5


class TopicsUnavailable(ImportError):
    """gensim is not installed."""


class TooFewNotes(ValueError):
    """The principal cannot read enough text to fit a topic model."""


class NoSuchNote(LookupError):
    """No readable note at that path.

    Raised for a note that does not exist and for one the principal may not
    read alike: telling them apart would confirm a path §12.3 says the
    requester is not entitled to know about.
    """


def default_num_topics(note_count: int) -> int:
    """Latent dimensions for a vault of this size: about its square root.

    Too many and the model degenerates into term matching, because with as many
    dimensions as notes each note gets its own; too few and distinct subjects
    share one. A fixed number would be wrong at both ends of the range a vault
    spans.
    """
    return max(2, min(MAX_TOPICS, round(math.sqrt(note_count))))


@dataclass(frozen=True)
class _Model:
    notes: list[IndexedNode]  # row i of ``vectors`` describes notes[i]
    row: dict[str, int]  # path -> row
    dictionary: Any
    tfidf: Any
    lsi: Any
    vectors: Any  # (notes, topics), each row unit length, or zero for no signal


def _unit(sparse: Any, size: int) -> Any:
    """A gensim sparse vector as a unit-length array, or None if it is all zero."""
    vec = np.zeros(size)
    for i, weight in sparse:
        vec[i] = weight
    norm = float(np.linalg.norm(vec))
    return vec / norm if norm > 0 else None


def _fit(principal_id: str, notes: list[IndexedNode], num_topics: int | None) -> _Model:
    if models is None:
        raise TopicsUnavailable(
            "topic search needs gensim: pip install 'basalt-vault[topics]' "
            "(or `uv sync --extra topics` in a checkout)"
        )
    if len(notes) < MIN_NOTES:
        raise TooFewNotes(
            f"need at least {MIN_NOTES} readable notes with text to find by topic; "
            f"{principal_id} can read {len(notes)}"
        )
    tokens = [tokenize(n.body if n.body is not None else n.text or "") for n in notes]
    dictionary = corpora.Dictionary(tokens)
    topics = min(num_topics or default_num_topics(len(notes)), len(notes) - 1, len(dictionary) - 1)
    if topics < 2:
        raise TooFewNotes(
            f"the notes {principal_id} can read hold too few distinct words to find by topic"
        )

    bows = [dictionary.doc2bow(t) for t in tokens]
    tfidf = models.TfidfModel(bows)
    lsi = models.LsiModel(tfidf[bows], id2word=dictionary, num_topics=topics, random_seed=_SEED)

    vectors = np.zeros((len(notes), topics))
    for i, bow in enumerate(bows):
        vec = _unit(lsi[tfidf[bow]], topics)
        if vec is not None:
            vectors[i] = vec
    return _Model(
        notes=notes,
        row={n.path: i for i, n in enumerate(notes)},
        dictionary=dictionary,
        tfidf=tfidf,
        lsi=lsi,
        vectors=vectors,
    )


def _rank(
    model: _Model, vec: Any, *, skip: int | None, limit: int, min_score: float
) -> list[dict[str, Any]]:
    hits = []
    for i, score in enumerate(model.vectors @ vec):
        # Rounded so that near-ties are settled by path, below, and not by
        # which of two equal scores the floating point happened to favour.
        score = round(float(score), 5)
        if i == skip or score < min_score:
            continue
        n = model.notes[i]
        hits.append({"score": score, "id": n.id, "path": n.path, "kind": n.kind, "title": n.title})
    hits.sort(key=lambda h: (-h["score"], utf8_key(h["path"])))
    return hits[:limit]


class TopicSearch:
    """Topic search over one vault, for any principal.

    Models are fitted lazily and cached. The notes come from the vault's own
    indexes pass, so a stale ``Vault.built`` answers from the content it was
    built over, as ``Vault.search`` does.
    """

    def __init__(self, vault: Vault, *, num_topics: int | None = None) -> None:
        self.vault = vault
        self.num_topics = num_topics
        self._models: OrderedDict[tuple[str, tuple[str, ...]], _Model] = OrderedDict()

    def find(
        self, principal_id: str, query: str, *, limit: int = 10, min_score: float = MIN_SCORE
    ) -> list[dict[str, Any]]:
        """Notes the principal can read, ranked by how close they are in topic to ``query``.

        Words the model never saw in any readable note carry no signal, so a
        query made only of them finds nothing.
        """
        model = self._model(principal_id)
        bow = model.dictionary.doc2bow(tokenize(query))
        vec = _unit(model.lsi[model.tfidf[bow]], model.lsi.num_topics)
        if vec is None:
            return []
        return _rank(model, vec, skip=None, limit=limit, min_score=min_score)

    def related(
        self, principal_id: str, path: str, *, limit: int = 10, min_score: float = MIN_SCORE
    ) -> list[dict[str, Any]]:
        """Notes on the same topics as the one at ``path``, which is not itself returned."""
        model = self._model(principal_id)
        row = model.row.get(nfc(path))
        if row is None:
            raise NoSuchNote(f"no readable note at {path!r}")
        return _rank(model, model.vectors[row], skip=row, limit=limit, min_score=min_score)

    def _model(self, principal_id: str) -> _Model:
        if self.vault.built is None:
            self.vault.reindex()
        built = self.vault.built
        assert built is not None

        # The eligibility of search.json (§10.5), narrowed to what this
        # principal may read: the predicate Vault.search applies per hit.
        readable = sorted(
            (
                n
                for n in built.node_records
                if n.id
                and n.text is not None
                and self.vault.can(principal_id, n.path, ["read"]).allowed
            ),
            key=lambda n: utf8_key(n.path),
        )
        key = (built.digest["root"], tuple(n.id for n in readable if n.id))

        cached = self._models.get(key)
        if cached is not None:
            self._models.move_to_end(key)
            return cached

        model = _fit(principal_id, readable, self.num_topics)
        self._models[key] = model
        while len(self._models) > MAX_MODELS:
            self._models.popitem(last=False)
        return model


__all__ = [
    "MAX_MODELS",
    "MAX_TOPICS",
    "MIN_NOTES",
    "MIN_SCORE",
    "NoSuchNote",
    "TooFewNotes",
    "TopicSearch",
    "TopicsUnavailable",
    "default_num_topics",
]
