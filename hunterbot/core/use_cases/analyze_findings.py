from hunterbot.core.domain import ScanAnalysis
from hunterbot.core.interfaces import FindingAnalyzer, FindingRepository, KnowledgeRepository


class AnalyzeFindingsUseCase:
    """Pulls stored Findings and runs a FindingAnalyzer's reasoning pass over them.

    ``knowledge_repository`` is optional: when supplied, the KnowledgeItems
    already linked to the pulled Findings via their ``knowledge_source_id``
    are resolved and handed to the analyzer as extra grounding context.
    """

    def __init__(
        self,
        *,
        finding_repository: FindingRepository,
        analyzer: FindingAnalyzer,
        knowledge_repository: KnowledgeRepository | None = None,
    ) -> None:
        self._findings = finding_repository
        self._analyzer = analyzer
        self._knowledge = knowledge_repository

    def execute(self, *, affected_asset: str | None = None) -> ScanAnalysis:
        findings = (
            self._findings.list_by_asset(affected_asset)
            if affected_asset is not None
            else self._findings.list_all()
        )

        knowledge_context = None
        if self._knowledge is not None:
            knowledge_ids = {f.knowledge_source_id for f in findings if f.knowledge_source_id is not None}
            knowledge_context = [
                item
                for item in (self._knowledge.get(knowledge_id) for knowledge_id in knowledge_ids)
                if item is not None
            ]

        return self._analyzer.analyze(findings=findings, knowledge_context=knowledge_context)
