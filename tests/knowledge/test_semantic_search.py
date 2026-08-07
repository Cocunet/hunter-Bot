import pytest
from sqlalchemy.orm import Session

from hunterbot.core.domain import KnowledgeItem, SourceType, VulnerabilityCategory
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.knowledge.search import SemanticKnowledgeSearchService, TfidfSemanticIndex
from hunterbot.knowledge.search import semantic_index as semantic_index_module
from hunterbot.storage.repositories import SqlAlchemyKnowledgeRepository, SqlAlchemySourceRepository


def _seed(session: Session, *, title: str, summary: str, content_hash: str) -> None:
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name=title, source_type=SourceType.DOCUMENTATION
    )
    SqlAlchemyKnowledgeRepository(session).add(
        KnowledgeItem(
            source_id=source.id,
            category=VulnerabilityCategory.OTHER,
            title=title,
            summary=summary,
            content_hash=content_hash.ljust(64, "0"),
        )
    )


class TestTfidfSemanticIndex:
    def test_is_available_reflects_sklearn_presence(self) -> None:
        assert TfidfSemanticIndex().is_available() is True

    def test_is_available_false_when_sklearn_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(semantic_index_module, "_SKLEARN_AVAILABLE", False)
        assert TfidfSemanticIndex().is_available() is False

    def test_search_raises_when_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(semantic_index_module, "_SKLEARN_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="semantic search backend unavailable"):
            TfidfSemanticIndex().search(query="anything", items=[])

    def test_search_ranks_more_similar_item_first(self) -> None:
        sql_item = KnowledgeItem(
            source_id=1,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection in login form",
            summary="Untrusted input concatenated into a SQL query allows database manipulation.",
            content_hash="a" * 64,
        )
        headers_item = KnowledgeItem(
            source_id=1,
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            title="Missing Content-Security-Policy header",
            summary="Absence of CSP headers can allow clickjacking and script injection attacks.",
            content_hash="b" * 64,
        )

        matches = TfidfSemanticIndex().search(
            query="database query injection attack", items=[headers_item, sql_item], top_k=10
        )

        assert matches[0].item.title == "SQL Injection in login form"
        assert matches[0].score > 0

    def test_search_respects_top_k(self) -> None:
        items = [
            KnowledgeItem(
                source_id=1,
                category=VulnerabilityCategory.OTHER,
                title=f"Injection variant {i}",
                summary="SQL injection database query attack vulnerability",
                content_hash=str(i) * 64,
            )
            for i in range(5)
        ]

        matches = TfidfSemanticIndex().search(query="injection attack", items=items, top_k=2)

        assert len(matches) <= 2

    def test_search_with_no_items_returns_empty(self) -> None:
        assert TfidfSemanticIndex().search(query="anything", items=[]) == []


class TestSemanticKnowledgeSearchService:
    def test_is_available_delegates_to_index(self) -> None:
        service = SemanticKnowledgeSearchService(
            knowledge_repository=None, semantic_index=TfidfSemanticIndex()  # type: ignore[arg-type]
        )
        assert service.is_available() is True

    def test_search_ranks_items_from_repository(self, session: Session) -> None:
        _seed(
            session,
            title="SQL Injection",
            summary="Untrusted input concatenated into a database query.",
            content_hash="a",
        )
        _seed(
            session,
            title="Missing Security Headers",
            summary="Absence of CSP and X-Frame-Options headers.",
            content_hash="b",
        )
        service = SemanticKnowledgeSearchService(
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
            semantic_index=TfidfSemanticIndex(),
        )

        matches = service.search(query="database query injection", top_k=5)

        assert matches[0].item.title == "SQL Injection"
