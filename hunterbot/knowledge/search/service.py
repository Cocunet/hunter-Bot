from hunterbot.core.domain import KnowledgeItem
from hunterbot.core.interfaces import KnowledgeRepository, SemanticIndex, SemanticMatch


class KnowledgeSearchService:
    """Keyword and metadata search over the structured knowledge base.

    See SemanticKnowledgeSearchService below for the optional vector-based
    alternative — kept as a separate class since it depends on an extra
    (SemanticIndex), not because the results are combined; a caller picks
    whichever matches the query it has (exact filters vs. free text).
    """

    def __init__(self, knowledge_repository: KnowledgeRepository) -> None:
        self._knowledge = knowledge_repository

    def search(
        self,
        *,
        keyword: str | None = None,
        category: str | None = None,
        cwe: str | None = None,
        owasp_category: str | None = None,
        severity: str | None = None,
        tag: str | None = None,
    ) -> list[KnowledgeItem]:
        return self._knowledge.search(
            keyword=keyword,
            category=category,
            cwe=cwe,
            owasp_category=owasp_category,
            severity=severity,
            tag=tag,
        )


class SemanticKnowledgeSearchService:
    """Ranks the knowledge base by similarity to a free-text query.

    Optional: depends on a SemanticIndex backend that may not be installed
    (see TfidfSemanticIndex). Callers should check ``is_available()`` first
    — e.g. to fall back to KnowledgeSearchService's keyword search — rather
    than only handling the RuntimeError ``search`` raises when unavailable.
    """

    def __init__(self, *, knowledge_repository: KnowledgeRepository, semantic_index: SemanticIndex) -> None:
        self._knowledge = knowledge_repository
        self._index = semantic_index

    def is_available(self) -> bool:
        return self._index.is_available()

    def search(self, *, query: str, top_k: int = 10) -> list[SemanticMatch]:
        all_items = self._knowledge.search()
        return self._index.search(query=query, items=all_items, top_k=top_k)
