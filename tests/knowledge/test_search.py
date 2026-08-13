import hashlib

from sqlalchemy.orm import Session

from hunterbot.core.domain import KnowledgeItem, Severity, SourceType, VulnerabilityCategory
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.knowledge.search import KnowledgeSearchService
from hunterbot.storage.repositories import SqlAlchemyKnowledgeRepository, SqlAlchemySourceRepository


def _seed_item(
    session: Session,
    *,
    title: str,
    category: VulnerabilityCategory,
    cwe: str | None = None,
    severity_hint: Severity | None = None,
    tags: tuple[str, ...] = (),
) -> None:
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name=title, source_type=SourceType.DOCUMENTATION
    )
    SqlAlchemyKnowledgeRepository(session).add(
        KnowledgeItem(
            source_id=source.id,
            category=category,
            title=title,
            summary=f"Summary for {title}",
            content_hash=hashlib.sha256(title.encode()).hexdigest(),
            cwe=cwe,
            severity_hint=severity_hint,
            tags=tags,
        )
    )


class TestKnowledgeSearchService:
    def test_search_by_keyword(self, session: Session) -> None:
        _seed_item(session, title="SQL Injection Basics", category=VulnerabilityCategory.INPUT_VALIDATION)
        _seed_item(session, title="Clickjacking", category=VulnerabilityCategory.MISSING_SECURITY_HEADERS)

        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
        results = service.search(keyword="Injection")

        assert [item.title for item in results] == ["SQL Injection Basics"]

    def test_search_by_category(self, session: Session) -> None:
        _seed_item(session, title="SQL Injection Basics", category=VulnerabilityCategory.INPUT_VALIDATION)
        _seed_item(session, title="Clickjacking", category=VulnerabilityCategory.MISSING_SECURITY_HEADERS)

        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
        results = service.search(category=VulnerabilityCategory.MISSING_SECURITY_HEADERS.value)

        assert [item.title for item in results] == ["Clickjacking"]

    def test_search_by_cwe(self, session: Session) -> None:
        _seed_item(session, title="XSS", category=VulnerabilityCategory.INPUT_VALIDATION, cwe="CWE-79")
        _seed_item(session, title="SQLi", category=VulnerabilityCategory.INPUT_VALIDATION, cwe="CWE-89")

        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
        results = service.search(cwe="CWE-79")

        assert [item.title for item in results] == ["XSS"]

    def test_search_by_tag(self, session: Session) -> None:
        _seed_item(
            session,
            title="XSS",
            category=VulnerabilityCategory.INPUT_VALIDATION,
            tags=("cross-site scripting", "xss"),
        )
        _seed_item(session, title="SQLi", category=VulnerabilityCategory.INPUT_VALIDATION, tags=("sql injection",))

        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))
        results = service.search(tag="xss")

        assert [item.title for item in results] == ["XSS"]

    def test_search_with_no_filters_returns_everything(self, session: Session) -> None:
        _seed_item(session, title="XSS", category=VulnerabilityCategory.INPUT_VALIDATION)
        _seed_item(session, title="Clickjacking", category=VulnerabilityCategory.MISSING_SECURITY_HEADERS)

        service = KnowledgeSearchService(SqlAlchemyKnowledgeRepository(session))

        assert len(service.search()) == 2
