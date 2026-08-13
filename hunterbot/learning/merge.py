from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from hunterbot.core.domain import KnowledgeItem, KnowledgeItemRevision
from hunterbot.core.interfaces import KnowledgeRepository, KnowledgeRevisionRepository
from hunterbot.learning.diff_engine import KnowledgeDiff, KnowledgeDiffKind


class MergeAction(str, Enum):
    ADDED = "added"
    SKIPPED = "skipped"
    UPDATED = "updated"


@dataclass(frozen=True)
class KnowledgeMergeResult:
    action: MergeAction
    item: KnowledgeItem
    previous_version: int | None = None


class KnowledgeMergeService:
    """Applies a KnowledgeDiff to the knowledge base.

    - NEW candidates are inserted as-is.
    - DUPLICATE candidates are skipped; the existing item is returned
      unchanged (no version bump, since nothing actually changed).
    - UPDATED candidates cause the *current* field values of the existing
      item to be archived as a KnowledgeItemRevision first, then the item
      row is overwritten with the candidate's values at ``version + 1``.
      History is never lost even though the live row is mutated in place.
    """

    def __init__(
        self,
        *,
        knowledge_repository: KnowledgeRepository,
        revision_repository: KnowledgeRevisionRepository,
    ) -> None:
        self._knowledge = knowledge_repository
        self._revisions = revision_repository

    def apply(self, diff: KnowledgeDiff) -> KnowledgeMergeResult:
        if diff.kind == KnowledgeDiffKind.DUPLICATE:
            assert diff.existing is not None
            return KnowledgeMergeResult(action=MergeAction.SKIPPED, item=diff.existing)

        if diff.kind == KnowledgeDiffKind.NEW:
            saved = self._knowledge.add(diff.candidate)
            return KnowledgeMergeResult(action=MergeAction.ADDED, item=saved)

        return self._apply_update(diff)

    def _apply_update(self, diff: KnowledgeDiff) -> KnowledgeMergeResult:
        existing = diff.existing
        assert existing is not None and existing.id is not None

        self._revisions.add(
            KnowledgeItemRevision(
                knowledge_item_id=existing.id,
                version=existing.version,
                title=existing.title,
                summary=existing.summary,
                content_hash=existing.content_hash,
                cwe=existing.cwe,
                owasp_category=existing.owasp_category,
                severity_hint=existing.severity_hint,
                tags=existing.tags,
                references=existing.references,
            )
        )

        updated_item = diff.candidate.model_copy(
            update={
                "id": existing.id,
                "version": existing.version + 1,
                "created_at": existing.created_at,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        saved = self._knowledge.update(updated_item)
        return KnowledgeMergeResult(action=MergeAction.UPDATED, item=saved, previous_version=existing.version)
