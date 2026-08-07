from hunterbot.core.domain import KnowledgeItem
from hunterbot.core.interfaces import SemanticMatch

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    _SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatched flag in tests
    _SKLEARN_AVAILABLE = False


class TfidfSemanticIndex:
    """Default SemanticIndex backend: TF-IDF vectors + cosine similarity.

    This is a classical statistical vector-space model, not a deep-learning
    embedding model — it ranks by term overlap/weighting rather than deeper
    semantic meaning. The tradeoff is deliberate: it needs no model
    download and no network access, which matters for a tool meant to run
    fully locally. It satisfies the same SemanticIndex contract a
    dense-embedding backend (sentence-transformers vectors indexed in FAISS
    or Chroma, per the original tech-stack options) would, so upgrading
    later is a matter of adding a new class, not changing any caller.

    Requires the optional ``scikit-learn`` dependency
    (``pip install "hunterbot[semantic]"``); ``is_available()`` reports
    whether it's actually usable in the current environment.
    """

    def is_available(self) -> bool:
        return _SKLEARN_AVAILABLE

    def search(self, *, query: str, items: list[KnowledgeItem], top_k: int = 10) -> list[SemanticMatch]:
        if not _SKLEARN_AVAILABLE:
            raise RuntimeError(
                "semantic search backend unavailable: install the 'semantic' extra "
                '(pip install "hunterbot[semantic]") to enable it'
            )
        if not items:
            return []

        corpus = [f"{item.title} {item.summary}" for item in items]
        vectorizer = TfidfVectorizer(stop_words="english")
        matrix = vectorizer.fit_transform([*corpus, query])
        item_vectors, query_vector = matrix[:-1], matrix[-1]
        similarities = cosine_similarity(query_vector, item_vectors)[0]

        ranked = sorted(zip(items, similarities), key=lambda pair: pair[1], reverse=True)
        return [SemanticMatch(item=item, score=float(score)) for item, score in ranked[:top_k] if score > 0]
