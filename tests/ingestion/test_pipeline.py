from pathlib import Path

from sqlalchemy.orm import Session

from hunterbot.core.domain import Source, SourceType
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.ingestion.connectors import MarkdownFileConnector
from hunterbot.ingestion.pipeline import IngestionPipeline
from hunterbot.knowledge.extraction import RuleBasedExtractor
from hunterbot.storage.repositories import (
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemySourceRepository,
)

_MARKDOWN = """# Broken Access Control

Broken access control lets an attacker perform privilege escalation and act
outside their intended permissions, a form of authorization bypass. This is
tracked as CWE-284 and A01:2021 in the OWASP Top 10.

This paragraph has no vulnerability keywords in it whatsoever, just filler.
"""

# RuleBasedExtractor derives a KnowledgeItem's title from the first ~120
# characters of its paragraph text (see rule_based._derive_title), which is
# also the identity signal KnowledgeDiffEngine uses to match revisions. This
# revision keeps the opening of the paragraph byte-identical to _MARKDOWN
# and only appends new content at the end, so the derived title (and thus
# identity) stays the same while content_hash changes -- exactly the
# "updated" case the diff engine is meant to detect.
_MARKDOWN_REVISED = """# Broken Access Control

Broken access control lets an attacker perform privilege escalation and act
outside their intended permissions, a form of authorization bypass. This is
tracked as CWE-284 and A01:2021 in the OWASP Top 10. Recent research shows
this extends to nearly every protected resource, not just isolated
endpoints.

This paragraph has no vulnerability keywords in it whatsoever, just filler.
"""


def _build_pipeline(
    session: Session,
) -> tuple[IngestionPipeline, SqlAlchemySourceRepository, SqlAlchemyKnowledgeRepository]:
    source_repo = SqlAlchemySourceRepository(session)
    knowledge_repo = SqlAlchemyKnowledgeRepository(session)
    pipeline = IngestionPipeline(
        source_repository=source_repo,
        knowledge_repository=knowledge_repo,
        knowledge_revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
        extractor=RuleBasedExtractor(),
    )
    return pipeline, source_repo, knowledge_repo


class TestIngestionPipeline:
    def test_ingest_extracts_and_persists_knowledge_items(self, session: Session, tmp_path: Path) -> None:
        pipeline, source_repo, _ = _build_pipeline(session)
        source = RegisterSourceUseCase(source_repo).execute(
            name="PortSwigger Academy", source_type=SourceType.WRITEUP
        )
        doc_path = tmp_path / "access-control.md"
        doc_path.write_text(_MARKDOWN, encoding="utf-8")

        result = pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))

        assert result.items_extracted == 1
        assert result.items_added == 1
        assert result.items_updated == 0
        assert result.items_unchanged == 0
        assert result.source.last_fetched_at is not None

    def test_ingest_is_unchanged_on_identical_rerun(self, session: Session, tmp_path: Path) -> None:
        pipeline, source_repo, _ = _build_pipeline(session)
        source = RegisterSourceUseCase(source_repo).execute(
            name="PortSwigger Academy", source_type=SourceType.WRITEUP
        )
        doc_path = tmp_path / "access-control.md"
        doc_path.write_text(_MARKDOWN, encoding="utf-8")

        pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))
        second_result = pipeline.ingest(source=source, connector=MarkdownFileConnector(doc_path))

        assert second_result.items_added == 0
        assert second_result.items_updated == 0
        assert second_result.items_unchanged == 1

    def test_ingest_updates_and_versions_on_revised_content(
        self, session: Session, tmp_path: Path
    ) -> None:
        pipeline, source_repo, knowledge_repo = _build_pipeline(session)
        source = RegisterSourceUseCase(source_repo).execute(
            name="PortSwigger Academy", source_type=SourceType.WRITEUP
        )
        original_path = tmp_path / "access-control.md"
        original_path.write_text(_MARKDOWN, encoding="utf-8")
        first_result = pipeline.ingest(source=source, connector=MarkdownFileConnector(original_path))

        revised_path = tmp_path / "access-control-v2.md"
        revised_path.write_text(_MARKDOWN_REVISED, encoding="utf-8")
        second_result = pipeline.ingest(source=source, connector=MarkdownFileConnector(revised_path))

        assert second_result.items_added == 0
        assert second_result.items_updated == 1
        assert second_result.items_unchanged == 0

        items = knowledge_repo.list_by_source(source.id)
        assert len(items) == 1
        assert items[0].version == 2
        assert "Recent research shows this extends" in items[0].summary
        assert first_result.items_added == 1

    def test_ingest_requires_registered_source(self, session: Session, tmp_path: Path) -> None:
        pipeline, _, _ = _build_pipeline(session)

        unpersisted_source = Source(name="Unregistered", source_type=SourceType.BLOG)
        doc_path = tmp_path / "doc.md"
        doc_path.write_text("content", encoding="utf-8")

        try:
            pipeline.ingest(source=unpersisted_source, connector=MarkdownFileConnector(doc_path))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for unregistered source")
