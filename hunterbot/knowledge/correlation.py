import re

from hunterbot.core.domain import Finding, KnowledgeItem
from hunterbot.core.interfaces import KnowledgeRepository

_STOPWORDS = frozenset(
    {
        "the", "a", "an", "is", "are", "was", "were", "this", "that", "these", "those",
        "and", "or", "but", "for", "with", "from", "into", "onto", "of", "to", "in", "on",
        "at", "by", "as", "it", "its", "be", "been", "being", "which", "can", "could",
        "may", "might", "will", "would", "should", "has", "have", "had", "not", "no",
    }
)
_WORD_PATTERN = re.compile(r"[a-z0-9][a-z0-9\-]{2,}")


def _significant_words(text: str) -> set[str]:
    return {word for word in _WORD_PATTERN.findall(text.lower()) if word not in _STOPWORDS}


class KnowledgeCorrelationService:
    """Links a scanner Finding to the KnowledgeItem that best explains it.

    Implements hunterbot.core.interfaces.KnowledgeCorrelator. Matching is
    deliberately simple and auditable: only KnowledgeItems in the same
    VulnerabilityCategory are considered, and among those the one sharing
    the most significant words with the finding's title/description wins.
    Ties and an empty/irrelevant knowledge base both resolve to "no match"
    (None) rather than a guess — correlation is additive, so a scan must
    never be blocked or degraded by the state of the knowledge base.
    """

    def __init__(self, knowledge_repository: KnowledgeRepository) -> None:
        self._knowledge = knowledge_repository

    def correlate(self, finding: Finding) -> int | None:
        candidates = self._knowledge.search(category=finding.category.value)
        if not candidates:
            return None

        finding_words = _significant_words(f"{finding.title} {finding.description}")
        if not finding_words:
            return None

        best_item: KnowledgeItem | None = None
        best_score = 0
        for item in candidates:
            item_words = _significant_words(f"{item.title} {item.summary} {' '.join(item.tags)}")
            score = len(finding_words & item_words)
            if score > best_score:
                best_score = score
                best_item = item

        return best_item.id if best_item is not None else None
