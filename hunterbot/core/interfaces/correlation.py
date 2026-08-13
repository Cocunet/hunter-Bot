from typing import Protocol

from hunterbot.core.domain import Finding


class KnowledgeCorrelator(Protocol):
    """Links a scanner Finding to the KnowledgeItem that best explains it.

    Optional by design: a caller (e.g. RunScanUseCase) that has none simply
    skips correlation. Concrete implementations decide the matching
    strategy — see hunterbot.knowledge.correlation.KnowledgeCorrelationService
    for the default (same-category, keyword-overlap) implementation.
    """

    def correlate(self, finding: Finding) -> int | None:
        """Return the id of the best-matching KnowledgeItem, or None."""
        ...
