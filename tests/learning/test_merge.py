import hashlib

from sqlalchemy.orm import Session

from hunterbot.core.domain import KnowledgeItem, SourceType, VulnerabilityCategory
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.learning import KnowledgeDiffEngine, KnowledgeMergeService, MergeAction
from hunterbot.storage.repositories import (
    SqlAlchemyKnowledgeRepository,
    SqlAlchemyKnowledgeRevisionRepository,
    SqlAlchemySourceRepository,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _register_source(session: Session) -> int:
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name="Test Source", source_type=SourceType.DOCUMENTATION
    )
    return source.id


class TestKnowledgeMergeService:
    def test_new_diff_adds_item(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        diff_engine = KnowledgeDiffEngine(knowledge_repo)
        merge_service = KnowledgeMergeService(
            knowledge_repository=knowledge_repo,
            revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
        )
        candidate = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="summary",
            content_hash=_hash("body"),
        )

        result = merge_service.apply(diff_engine.diff(candidate))

        assert result.action == MergeAction.ADDED
        assert result.item.id is not None
        assert result.item.version == 1

    def test_duplicate_diff_is_skipped_without_version_bump(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        diff_engine = KnowledgeDiffEngine(knowledge_repo)
        merge_service = KnowledgeMergeService(
            knowledge_repository=knowledge_repo,
            revision_repository=SqlAlchemyKnowledgeRevisionRepository(session),
        )
        candidate = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="summary",
            content_hash=_hash("body"),
        )
        first = merge_service.apply(diff_engine.diff(candidate))

        second = merge_service.apply(diff_engine.diff(candidate))

        assert second.action == MergeAction.SKIPPED
        assert second.item.id == first.item.id
        assert second.item.version == 1

    def test_updated_diff_bumps_version_and_archives_revision(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        revision_repo = SqlAlchemyKnowledgeRevisionRepository(session)
        diff_engine = KnowledgeDiffEngine(knowledge_repo)
        merge_service = KnowledgeMergeService(
            knowledge_repository=knowledge_repo, revision_repository=revision_repo
        )
        original = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="original summary",
            content_hash=_hash("body v1"),
        )
        added = merge_service.apply(diff_engine.diff(original))

        revised_candidate = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="revised summary",
            content_hash=_hash("body v2"),
        )
        result = merge_service.apply(diff_engine.diff(revised_candidate))

        assert result.action == MergeAction.UPDATED
        assert result.previous_version == 1
        assert result.item.id == added.item.id
        assert result.item.version == 2
        assert result.item.summary == "revised summary"

        history = revision_repo.list_by_knowledge_item(added.item.id)
        assert len(history) == 1
        assert history[0].version == 1
        assert history[0].summary == "original summary"

    def test_two_updates_preserve_full_history(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        revision_repo = SqlAlchemyKnowledgeRevisionRepository(session)
        diff_engine = KnowledgeDiffEngine(knowledge_repo)
        merge_service = KnowledgeMergeService(
            knowledge_repository=knowledge_repo, revision_repository=revision_repo
        )

        v1 = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="v1",
            content_hash=_hash("body v1"),
        )
        added = merge_service.apply(diff_engine.diff(v1))

        v2 = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="v2",
            content_hash=_hash("body v2"),
        )
        merge_service.apply(diff_engine.diff(v2))

        v3 = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="v3",
            content_hash=_hash("body v3"),
        )
        final = merge_service.apply(diff_engine.diff(v3))

        assert final.item.version == 3
        history = revision_repo.list_by_knowledge_item(added.item.id)
        assert [r.version for r in history] == [1, 2]
        assert [r.summary for r in history] == ["v1", "v2"]
