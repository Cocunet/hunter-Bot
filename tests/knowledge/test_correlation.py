import hashlib

from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    Confidence,
    Finding,
    KnowledgeItem,
    Severity,
    SourceType,
    VulnerabilityCategory,
)
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.storage.repositories import SqlAlchemyKnowledgeRepository, SqlAlchemySourceRepository


def _seed_item(
    session: Session,
    *,
    title: str,
    category: VulnerabilityCategory,
    summary: str = "",
    tags: tuple[str, ...] = (),
) -> KnowledgeItem:
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name=title, source_type=SourceType.DOCUMENTATION
    )
    return SqlAlchemyKnowledgeRepository(session).add(
        KnowledgeItem(
            source_id=source.id,
            category=category,
            title=title,
            summary=summary or f"Summary for {title}",
            content_hash=hashlib.sha256(title.encode()).hexdigest(),
            tags=tags,
        )
    )


def _finding(title: str, description: str, category: VulnerabilityCategory) -> Finding:
    return Finding(
        title=title,
        category=category,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=description,
        affected_asset="https://example.com",
        location="https://example.com/",
        scanner_name="test-scanner",
    )


class TestKnowledgeCorrelationService:
    def test_correlates_to_best_matching_item_in_same_category(self, session: Session) -> None:
        clickjacking = _seed_item(
            session,
            title="Clickjacking via missing X-Frame-Options",
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            summary="Missing X-Frame-Options header allows clickjacking attacks.",
            tags=("clickjacking", "headers"),
        )
        _seed_item(
            session,
            title="Missing Strict-Transport-Security",
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            summary="Missing HSTS header weakens transport security.",
        )
        finding = _finding(
            "Missing X-Frame-Options header",
            "The response is missing the X-Frame-Options header, enabling clickjacking.",
            VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        )

        service = KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session))
        result = service.correlate(finding)

        assert result == clickjacking.id

    def test_returns_none_when_no_items_in_category(self, session: Session) -> None:
        finding = _finding(
            "Directory listing enabled",
            "The server exposes a directory listing.",
            VulnerabilityCategory.INFORMATION_DISCLOSURE,
        )

        service = KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session))
        result = service.correlate(finding)

        assert result is None

    def test_returns_none_when_no_words_overlap(self, session: Session) -> None:
        _seed_item(
            session,
            title="Something entirely unrelated",
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            summary="Completely different concepts and vocabulary here.",
        )
        finding = _finding(
            "Zzz Qqq Www header issue",
            "Totally distinct wording from the knowledge base entry.",
            VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        )

        service = KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session))
        result = service.correlate(finding)

        assert result is None
