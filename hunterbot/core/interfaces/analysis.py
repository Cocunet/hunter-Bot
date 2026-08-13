from __future__ import annotations

from typing import Protocol

from hunterbot.core.domain import Finding, KnowledgeItem, ScanAnalysis


class FindingAnalyzer(Protocol):
    """Reasons about a set of Findings: per-finding triage plus attack chains.

    Optional by design, like KnowledgeExtractor's LLM backend: a caller
    (e.g. AnalyzeFindingsUseCase) that has none simply doesn't offer
    analysis. ``knowledge_context`` is the KnowledgeItems already linked to
    these Findings via KnowledgeCorrelator, if any — extra grounding for the
    analyzer, not a requirement.
    """

    def analyze(
        self, *, findings: list[Finding], knowledge_context: list[KnowledgeItem] | None = None
    ) -> ScanAnalysis: ...
