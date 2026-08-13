from dataclasses import dataclass
from enum import Enum

from hunterbot.core.domain import KnowledgeItem
from hunterbot.core.interfaces import KnowledgeRepository


class KnowledgeDiffKind(str, Enum):
    """How a freshly extracted KnowledgeItem relates to what's already stored."""

    NEW = "new"
    DUPLICATE = "duplicate"
    UPDATED = "updated"


@dataclass(frozen=True)
class KnowledgeDiff:
    kind: KnowledgeDiffKind
    candidate: KnowledgeItem
    existing: KnowledgeItem | None = None


class KnowledgeDiffEngine:
    """Classifies a candidate KnowledgeItem against the existing knowledge base.

    Two identity signals are used, in order:

    1. Exact ``content_hash`` match anywhere in the KB -> DUPLICATE. The
       content is byte-for-byte something we already know.
    2. Same ``(source_id, title)`` as an existing item, different hash ->
       UPDATED. This is the identity heuristic: within one source, a
       paragraph's title is treated as a stable handle for "the same piece
       of knowledge" even as its content is revised on re-ingestion. This is
       a deliberate simplification — sources with unstable/duplicate titles
       will misclassify revisions as brand-new items instead of updates.
    3. Neither -> NEW.
    """

    def __init__(self, knowledge_repository: KnowledgeRepository) -> None:
        self._knowledge = knowledge_repository

    def diff(self, candidate: KnowledgeItem) -> KnowledgeDiff:
        exact_match = self._knowledge.get_by_content_hash(candidate.content_hash)
        if exact_match is not None:
            return KnowledgeDiff(kind=KnowledgeDiffKind.DUPLICATE, candidate=candidate, existing=exact_match)

        identity_match = self._knowledge.find_by_source_and_title(candidate.source_id, candidate.title)
        if identity_match is not None:
            return KnowledgeDiff(kind=KnowledgeDiffKind.UPDATED, candidate=candidate, existing=identity_match)

        return KnowledgeDiff(kind=KnowledgeDiffKind.NEW, candidate=candidate)
