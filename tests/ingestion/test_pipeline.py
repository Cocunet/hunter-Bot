from pathlib import Path

from sqlalchemy.orm import Session

from hunterbot.core.domain import SourceType
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.ingestion.connectors import MarkdownFileConnector
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.extraction import RuleBasedExtractor
from hunterbot.storage.repositories import SqlAlchemyKnowledgeRepository, SqlAlchemySourceRepository

_MARKDOWN = """# Broken Access Control

Broken access control lets an attacker perform privilege escalation and act
outside their intended permissions, a form of authorization bypass. This is
tracked as CWE-284 and A01:2021 in the OWASP Top 10.

This paragraph has no vulnerability keywords in it whatsoever, just filler.
"""


def _build_pipeline(session: Session) -> tuple[IngestionPipeline, SqlAlchemySourceRepository]:
    source_repo = SqlAlchemySourceRepository(session)
    knowledge_repo = SqlAlchemyKnowledgeRepository(session)
    pipeline = IngestionPipeline(
        source_repository=source_repo,
        knowledge_repository=knowledge_repo,
        extractor=RuleBasedExtractor(),
    )
    return pipeline, source_repo


class TestIngestionPipeline:
    def test_ingest_extracts_and_persists_knowledge_items(self, session: Session, tmp_path: Path) -> None:
        pipeline, source_repo = _build_pipeline(session)
        source = RegisterSourceUseCase(source_repo).execute(
            name="PortSwigger Academy", source_type=SourceType.WRITEUP
        )
        doc_path = tmp_path / "access-control.md"
        doc_path.write_text(_MARKDOWN, encoding="utf-8")

        result = pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))

        assert result.items_extracted == 1
        assert result.items_added == 1
        assert result.items_deduplicated == 0
        assert result.source.last_fetched_at is not None

    def test_ingest_deduplicates_on_rerun(self, session: Session, tmp_path: Path) -> None:
        pipeline, source_repo = _build_pipeline(session)
        source = RegisterSourceUseCase(source_repo).execute(
            name="PortSwigger Academy", source_type=SourceType.WRITEUP
        )
        doc_path = tmp_path / "access-control.md"
        doc_path.write_text(_MARKDOWN, encoding="utf-8")

        pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))
        second_result = pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))

        assert second_result.items_added == 0
        assert second_result.items_deduplicated == 1

    def test_ingest_requires_registered_source(self, session: Session, tmp_path: Path) -> None:
        pipeline, _ = _build_pipeline(session)
        from hunterbot.core.domain import Source

        unpersisted_source = Source(name="Unregistered", source_type=SourceType.BLOG)
        doc_path = tmp_path / "doc.md"
        doc_path.write_text("content", encoding="utf-8")

        try:
            pipeline.ingest(source=unpersisted_source, connector=MarkdownFileConnector(doc_path))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for unregistered source")
