import hashlib

from sqlalchemy.orm import Session

from hunterbot.core.domain import KnowledgeItem, SourceType, VulnerabilityCategory
from hunterbot.core.use_cases.source_management import RegisterSourceUseCase
from hunterbot.learning import KnowledgeDiffEngine, KnowledgeDiffKind
from hunterbot.storage.repositories import SqlAlchemyKnowledgeRepository, SqlAlchemySourceRepository


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _register_source(session: Session) -> int:
    source = RegisterSourceUseCase(SqlAlchemySourceRepository(session)).execute(
        name="Test Source", source_type=SourceType.DOCUMENTATION
    )
    return source.id


class TestKnowledgeDiffEngine:
    def test_brand_new_item_is_new(self, session: Session) -> None:
        source_id = _register_source(session)
        engine = KnowledgeDiffEngine(SqlAlchemyKnowledgeRepository(session))
        candidate = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="summary",
            content_hash=_hash("sql injection body"),
        )

        diff = engine.diff(candidate)

        assert diff.kind == KnowledgeDiffKind.NEW
        assert diff.existing is None

    def test_identical_content_hash_is_duplicate(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        engine = KnowledgeDiffEngine(knowledge_repo)
        original = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="summary",
            content_hash=_hash("sql injection body"),
        )
        saved = knowledge_repo.add(original)

        diff = engine.diff(original)

        assert diff.kind == KnowledgeDiffKind.DUPLICATE
        assert diff.existing.id == saved.id

    def test_same_source_and_title_different_hash_is_updated(self, session: Session) -> None:
        source_id = _register_source(session)
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        engine = KnowledgeDiffEngine(knowledge_repo)
        original = knowledge_repo.add(
            KnowledgeItem(
                source_id=source_id,
                category=VulnerabilityCategory.INPUT_VALIDATION,
                title="SQL Injection",
                summary="original summary",
                content_hash=_hash("sql injection body v1"),
            )
        )
        candidate = KnowledgeItem(
            source_id=source_id,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="revised summary",
            content_hash=_hash("sql injection body v2"),
        )

        diff = engine.diff(candidate)

        assert diff.kind == KnowledgeDiffKind.UPDATED
        assert diff.existing.id == original.id

    def test_same_title_different_source_is_new(self, session: Session) -> None:
        knowledge_repo = SqlAlchemyKnowledgeRepository(session)
        engine = KnowledgeDiffEngine(knowledge_repo)
        source_a = _register_source(session)
        source_repo = SqlAlchemySourceRepository(session)
        source_b = RegisterSourceUseCase(source_repo).execute(
            name="Other Source", source_type=SourceType.BLOG
        ).id

        knowledge_repo.add(
            KnowledgeItem(
                source_id=source_a,
                category=VulnerabilityCategory.INPUT_VALIDATION,
                title="SQL Injection",
                summary="summary",
                content_hash=_hash("body from source a"),
            )
        )
        candidate = KnowledgeItem(
            source_id=source_b,
            category=VulnerabilityCategory.INPUT_VALIDATION,
            title="SQL Injection",
            summary="summary",
            content_hash=_hash("body from source b"),
        )

        diff = engine.diff(candidate)

        assert diff.kind == KnowledgeDiffKind.NEW
