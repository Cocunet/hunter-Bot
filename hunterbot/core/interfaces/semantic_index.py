from dataclasses import dataclass
from typing import Protocol

from hunterbot.core.domain import KnowledgeItem


@dataclass(frozen=True)
class SemanticMatch:
    item: KnowledgeItem
    score: float


class SemanticIndex(Protocol):
    """Optional vector-similarity search over a set of KnowledgeItems.

    This is deliberately a separate, optional capability from
    ``KnowledgeRepository.search`` (exact keyword/metadata filtering) — per
    the project brief, semantic search should be available *if* a vector
    backend is present, and skipped gracefully otherwise. Concrete
    implementations decide how text becomes vectors: the default backend
    (hunterbot.knowledge.search.semantic_index.TfidfSemanticIndex) uses
    TF-IDF and needs no model download or network access; a dense-embedding
    backend indexed in FAISS or Chroma can implement this same contract
    later without any caller changing.
    """

    def is_available(self) -> bool:
        """Whether this backend's dependencies are installed and usable."""
        ...

    def search(self, *, query: str, items: list[KnowledgeItem], top_k: int = 10) -> list[SemanticMatch]:
        """Rank ``items`` by similarity to ``query``, most similar first."""
        ...
