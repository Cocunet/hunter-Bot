import re
from pathlib import Path

from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    Confidence,
    Finding,
    Severity,
    SourceType,
    VulnerabilityCategory,
)
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.ingestion.connectors import connector_for_path
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.knowledge.extraction import RuleBasedExtractor
from hunterbot.storage.repositories import (
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemySourceRepository,
)

_DOC_PATH = (
    Path(__file__).resolve().parents[2] / "knowledge_sources" / "wstg-vulnerability-methodology.md"
)


def _ingest(session: Session):
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name="WSTG Vulnerability Methodology", source_type=SourceType.DOCUMENTATION
    )
    pipeline = IngestionPipeline(
        source_repository=SqlAlchemySourceRepository(session),
        knowledge_repository=SqlAlchemyKnowledgeRepository(session),
        knowledge_revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
        extractor=RuleBasedExtractor(),
    )
    return pipeline.ingest(source=source, connector=connector_for_path(str(_DOC_PATH)))


class TestWstgMethodologySource:
    """Guards the bundled 50-vulnerability WSTG reference against silent extraction loss.

    Every one of the original 50 numbered items (see the doc's own [#N]
    cross-references) needs at least one matching RuleBasedExtractor
    keyword to survive ingestion -- it's easy to describe a vulnerability
    accurately in prose without ever using one of the extractor's fixed
    keyword phrases, and a paragraph that doesn't match silently
    disappears rather than erroring. This test ingests the real file and
    checks that all 50 numbers are still traceable in what got extracted.
    """

    def test_all_fifty_numbered_items_survive_extraction(self, session: Session) -> None:
        result = _ingest(session)
        assert result.items_added == result.items_extracted
        assert result.items_extracted > 0

        items = SqlAlchemyKnowledgeRepository(session).list_by_source(result.source.id)
        covered_numbers: set[int] = set()
        for item in items:
            covered_numbers.update(int(n) for n in re.findall(r"#(\d+)\]", item.summary))

        missing = sorted(set(range(1, 51)) - covered_numbers)
        assert missing == [], f"item numbers dropped during extraction: {missing}"

    def test_items_already_automated_by_hunterbot_land_in_matching_categories(self, session: Session) -> None:
        _ingest(session)
        items = SqlAlchemyKnowledgeRepository(session).list_by_source(1)

        cors_item = next(item for item in items if "[#26]" in item.summary)
        assert cors_item.category == VulnerabilityCategory.SECURITY_MISCONFIGURATION

        xss_item = next(item for item in items if "[#2]" in item.summary)
        assert xss_item.category == VulnerabilityCategory.INPUT_VALIDATION

        open_redirect_item = next(item for item in items if "[#24]" in item.summary)
        assert open_redirect_item.category == VulnerabilityCategory.INPUT_VALIDATION

        idor_item = next(item for item in items if "[#4]" in item.summary)
        assert idor_item.category == VulnerabilityCategory.AUTHORIZATION_ISSUE

    def test_correlates_a_real_cors_finding_to_a_matching_entry(self, session: Session) -> None:
        _ingest(session)
        correlator = KnowledgeCorrelationService(SqlAlchemyKnowledgeRepository(session))

        finding = Finding(
            title="CORS policy combines wildcard origin with allowed credentials",
            category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                "https://example.com/ responds with Access-Control-Allow-Origin: * and "
                "Access-Control-Allow-Credentials: true at the same time."
            ),
            affected_asset="https://example.com",
            location="https://example.com/",
            scanner_name="cors-misconfiguration",
        )

        knowledge_source_id = correlator.correlate(finding)

        assert knowledge_source_id is not None
        matched = SqlAlchemyKnowledgeRepository(session).get(knowledge_source_id)
        assert "[#26]" in matched.summary
