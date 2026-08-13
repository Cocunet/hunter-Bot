import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    Confidence,
    Finding,
    KnowledgeItem,
    Severity,
    SourceType,
    VulnerabilityCategory,
)
from hunterbot.core.use_cases.generate_report import GenerateReportUseCase
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.reporting import MarkdownReportGenerator
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


class TestGenerateReportUseCase:
    def test_includes_all_findings_when_no_asset_filter(self, session: Session, tmp_path: Path) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com"))
        repo.add(_finding("https://b.example.com"))

        use_case = GenerateReportUseCase(finding_repository=repo, report_generator=MarkdownReportGenerator())
        output_path = use_case.execute(output_path=tmp_path / "report.md")

        content = output_path.read_text(encoding="utf-8")
        assert "Total findings: 2" in content

    def test_filters_by_affected_asset(self, session: Session, tmp_path: Path) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com"))
        repo.add(_finding("https://b.example.com"))

        use_case = GenerateReportUseCase(finding_repository=repo, report_generator=MarkdownReportGenerator())
        output_path = use_case.execute(
            output_path=tmp_path / "report.md", affected_asset="https://a.example.com"
        )

        content = output_path.read_text(encoding="utf-8")
        assert "Total findings: 1" in content

    def test_resolves_knowledge_titles_when_repository_supplied(self, session: Session, tmp_path: Path) -> None:
        source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
            name="Headers Guide", source_type=SourceType.DOCUMENTATION
        )
        item = SqlAlchemyKnowledgeRepository(session).add(
            KnowledgeItem(
                source_id=source.id,
                category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
                title="Missing X-Frame-Options",
                summary="Summary.",
                content_hash=hashlib.sha256(b"x-frame-options").hexdigest(),
            )
        )
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com", knowledge_source_id=item.id))

        use_case = GenerateReportUseCase(
            finding_repository=repo,
            report_generator=MarkdownReportGenerator(),
            knowledge_repository=SqlAlchemyKnowledgeRepository(session),
        )
        output_path = use_case.execute(output_path=tmp_path / "report.md")

        content = output_path.read_text(encoding="utf-8")
        assert "Missing X-Frame-Options" in content

    def test_without_knowledge_repository_falls_back_to_bare_id(self, session: Session, tmp_path: Path) -> None:
        repo = SqlAlchemyFindingRepository(session)
        repo.add(_finding("https://a.example.com", knowledge_source_id=999))

        use_case = GenerateReportUseCase(finding_repository=repo, report_generator=MarkdownReportGenerator())
        output_path = use_case.execute(output_path=tmp_path / "report.md")

        content = output_path.read_text(encoding="utf-8")
        assert "KnowledgeItem #999" in content
