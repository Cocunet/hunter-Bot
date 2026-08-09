from pathlib import Path

from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    Confidence,
    Finding,
    Severity,
    SourceType,
    VulnerabilityCategory,
)
from hunterbot.core.use_cases.scope_management import RegisterScopeUseCase
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.ingestion.connectors import connector_for_path
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.correlation import KnowledgeCorrelationService
from hunterbot.knowledge.extraction import RuleBasedExtractor
from hunterbot.storage.repositories import (
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemyScopeRepository,
    SqlAlchemySourceRepository,
)

_DOC_PATH = Path(__file__).resolve().parents[2] / "knowledge_sources" / "owasp-risk-rating-scale.md"


def _ingest(session: Session):
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name="OWASP Risk Rating Scale", source_type=SourceType.DOCUMENTATION
    )
    pipeline = IngestionPipeline(
        source_repository=SqlAlchemySourceRepository(session),
        knowledge_repository=SqlAlchemyKnowledgeRepository(session),
        knowledge_revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
        extractor=RuleBasedExtractor(),
    )
    return pipeline.ingest(source=source, connector=connector_for_path(str(_DOC_PATH)))


class TestOwaspRiskRatingSource:
    """Guards the bundled reference doc against silently breaking extraction.

    knowledge_sources/owasp-risk-rating-scale.md is written to be picked up
    by RuleBasedExtractor's keyword heuristics (see rule_based.py) -- every
    paragraph needs a category keyword, and most carry a CWE id and a
    severity phrase. An edit that loses those signals wouldn't fail loudly
    anywhere else, so this test ingests the real file and checks the things
    that actually matter: every vulnerability class extracts, with the right
    category and a severity gradient from mild to critical, and a real scan
    Finding correlates to the specific matching entry.
    """

    def test_ingests_all_four_vulnerability_classes_with_expected_categories(self, session: Session) -> None:
        result = _ingest(session)
        assert result.items_added == result.items_extracted
        assert result.items_extracted >= 16  # 4 variants x 4 classes, plus the intro paragraph

        items = SqlAlchemyKnowledgeRepository(session).list_by_source(result.source.id)
        by_category: dict[VulnerabilityCategory, list] = {}
        for item in items:
            by_category.setdefault(item.category, []).append(item)

        cors_items = by_category[VulnerabilityCategory.SECURITY_MISCONFIGURATION]
        assert len(cors_items) >= 4
        assert all(item.cwe == "CWE-942" for item in cors_items)

        xss_items = [item for item in items if item.cwe == "CWE-79"]
        assert len(xss_items) == 4
        assert {item.severity_hint for item in xss_items} == {
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        }

        race_items = [item for item in items if item.cwe == "CWE-362"]
        assert len(race_items) == 4

        upload_items = [item for item in items if item.cwe == "CWE-434"]
        assert len(upload_items) == 4

    def test_correlates_a_real_cors_finding_to_the_matching_entry(self, session: Session) -> None:
        _ingest(session)
        RegisterScopeUseCase(SqlAlchemyScopeRepository(session)).execute(
            target="example.com", program_name="Acme", authorized_by="Alice"
        )
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
        assert matched.cwe == "CWE-942"
        assert "wildcard" in matched.summary.lower()
        assert "allow-credentials: true" in matched.summary.lower()
