from hunterbot.core.domain import KnowledgeItem
from hunterbot.core.interfaces import KnowledgeRepository


class KnowledgeSearchService:
    """Keyword and metadata search over the structured knowledge base.

    Semantic (vector) search is intentionally not implemented here — per the
    approved architecture, a vector index is added later as an optional
    addition once the structured knowledge base is proven out, without
    changing this interface's callers.
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
