from __future__ import annotations

from typing import Protocol

from hunterbot.core.domain import KnowledgeItem, Source


class KnowledgeExtractor(Protocol):
    """Turns normalized text from a Source into structured KnowledgeItems.

    Implementations may be rule-based (see hunterbot.knowledge.extraction)
    or, in a later slice, LLM-backed — callers depend only on this contract.
    """

    def extract(self, *, text: str, source: Source) -> list[KnowledgeItem]: ...
