from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from hunterbot.api.dependencies import get_session
from hunterbot.api.schemas import KnowledgeHistoryResponse, SemanticMatchResponse, SemanticSearchResponse
from hunterbot.core.domain import KnowledgeItem
from hunterbot.knowledge.search import KnowledgeSearchService, SemanticKnowledgeSearchService, TfidfSemanticIndex
from hunterbot.storage import SqlAlchemyKnowledgeRepository, SqlAlchemyKnowledgeRevisionRepository

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/search", response_model=list[KnowledgeItem])
def search_knowledge(
    keyword: str | None = None,
    category: str | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    severity: str | None = None,
    tag: str | None = None,
    session: Session = Depends(get_session),
) -> list[KnowledgeItem]:
    """Search the structured knowledge base by keyword and/or exact metadata filters."""
    service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
    return service.search(
        keyword=keyword, category=category, cwe=cwe, owasp_category=owasp, severity=severity, tag=tag
    )


@router.get("/semantic-search", response_model=SemanticSearchResponse)
def semantic_search_knowledge(
    query: str, top_k: int = 10, session: Session = Depends(get_session)
) -> SemanticSearchResponse:
    """Rank the knowledge base by similarity to a free-text query.

    Optional: requires the 'semantic' extra (scikit-learn). Falls back to
    plain keyword search over the same query text if that isn't installed —
    ``used_semantic_backend`` tells the caller which path was taken.
    """
    knowledge_repo = SqlAlchemyKnowledgeRepository(session)
    semantic_service = SemanticKnowledgeSearchService(
        knowledge_repository=knowledge_repo, semantic_index=TfidfSemanticIndex()
    )

    if not semantic_service.is_available():
        results = KnowledgeSearchService(knowledge_repo).search(keyword=query)[:top_k]
        return SemanticSearchResponse(
            results=[SemanticMatchResponse(item=item, score=0.0) for item in results],
            used_semantic_backend=False,
        )

    matches = semantic_service.search(query=query, top_k=top_k)
    return SemanticSearchResponse(
        results=[SemanticMatchResponse(item=match.item, score=match.score) for match in matches],
        used_semantic_backend=True,
    )


@router.get("/{item_id}/history", response_model=KnowledgeHistoryResponse)
def knowledge_history(item_id: int, session: Session = Depends(get_session)) -> KnowledgeHistoryResponse:
    """Show the revision history of a knowledge item, oldest first."""
    knowledge_repo = SqlAlchemyKnowledgeRepository(session)
    current = knowledge_repo.get(item_id)
    if current is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No knowledge item with id {item_id}.")

    revisions = SqlAlchemyKnowledgeRevisionRepository(session).list_by_knowledge_item(item_id)
    return KnowledgeHistoryResponse(current=current, revisions=revisions)
