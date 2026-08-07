import hashlib

from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    Confidence,
    Finding,
    KnowledgeItem,
    ScanAnalysis,
    Severity,
    SourceType,
    VulnerabilityCategory,
)
from hunterbot.core.use_cases.analyze_findings import AnalyzeFindingsUseCase
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.storage.repositories import (
    SqlAlchemyFindingRepository,
    SqlAlchemyKnowledgeRepository,
    SqlAlchemySourceRepository,
)


def _finding(affected_asset: str, knowledge_source_id: int | None = None) -> Finding:
    return Finding(
        title="Test finding",
        category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Description.",
        affected_asset=affected_asset,
        location=affected_asset + "/",
        scanner_name="test-scanner",
        knowledge_source_id=knowledge_source_id,
    )


class _StubAnalyzer:
    def __init__(self, result: ScanAnalysis) -> None:
        self._result = result
        self.received_findings: list[Finding] | None = None
        self.received_knowledge_context: list[KnowledgeItem] | None = None

    def analyze(self, *, findings, knowledge_context=None) -> ScanAnalysis:
        self.received_findings = findings
        self.received_knowledge_context = knowledge_context
        return self._result


class TestAnalyzeFindingsUseCase:
    def test_analyzes_all_findings_when_no_asset_filter(self, session: Session) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com"))
        repo.add(_finding("https://b.example.com"))
        analyzer = _StubAnalyzer(ScanAnalysis(summary="ok"))

        use_case = AnalyzeFindingsUseCase(finding_repository=repo, analyzer=analyzer)
        result = use_case.execute()

        assert result.summary == "ok"
        assert len(analyzer.received_findings) == 2

    def test_filters_by_affected_asset(self, session: Session) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com"))
        repo.add(_finding("https://b.example.com"))
        analyzer = _StubAnalyzer(ScanAnalysis(summary="ok"))

        use_case = AnalyzeFindingsUseCase(finding_repository=repo, analyzer=analyzer)
        use_case.execute(affected_asset="https://a.example.com")

        assert len(analyzer.received_findings) == 1
        assert analyzer.received_findings[0].affected_asset == "https://a.example.com"

    def test_resolves_knowledge_context_when_repository_supplied(self, session: Session) -> None:
        source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
            name="Headers Guide", source_type=SourceType.DOCUMENTATION
        )
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        item = knowledge_repo.add(
            KnowledgeItem(
                source_id=source.id,
                category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
                title="Missing X-Frame-Options",
                summary="Summary.",
                content_hash=hashlib.sha256(b"x-frame-options").hexdigest(),
            )
        )
        finding_repo = SqlAlchemyFindingRepository(session)
        finding_repo.add(_finding("https://a.example.com", knowledge_source_id=item.id))
        analyzer = _StubAnalyzer(ScanAnalysis(summary="ok"))

        use_case = AnalyzeFindingsUseCase(
            finding_repository=finding_repo, analyzer=analyzer, knowledge_repository=knowledge_repo
        )
        use_case.execute()

        assert analyzer.received_knowledge_context is not None
        assert len(analyzer.received_knowledge_context) == 1
        assert analyzer.received_knowledge_context[0].title == "Missing X-Frame-Options"

    def test_no_knowledge_repository_passes_none(self, session: Session) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com"))
        analyzer = _StubAnalyzer(ScanAnalysis(summary="ok"))

        use_case = AnalyzeFindingsUseCase(finding_repository=repo, analyzer=analyzer)
        use_case.execute()

        assert analyzer.received_knowledge_context is None
