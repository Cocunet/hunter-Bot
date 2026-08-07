from pathlib import Path

from hunterbot.core.interfaces import FindingRepository, KnowledgeRepository, ReportGenerator


class GenerateReportUseCase:
    """Pulls Findings from storage and hands them to a ReportGenerator.

    Depends only on the FindingRepository, KnowledgeRepository, and
    ReportGenerator Protocols — which concrete storage backend and output
    format are used is decided by the caller (composition root), not this
    use-case.

    ``knowledge_repository`` is optional: when supplied, the unique
    ``knowledge_source_id``s among the reported Findings are resolved to
    their KnowledgeItem titles and handed to the generator as
    ``knowledge_titles``, so reports can render a readable label instead of
    a bare id. Without one, generators still work — they just fall back to
    rendering "KnowledgeItem #N".
    """

    def __init__(
        self,
        *,
        finding_repository: FindingRepository,
        report_generator: ReportGenerator,
        knowledge_repository: KnowledgeRepository | None = None,
    ) -> None:
        self._findings = finding_repository
        self._report_generator = report_generator
        self._knowledge = knowledge_repository

    def execute(self, *, output_path: Path, affected_asset: str | None = None) -> Path:
        findings = (
            self._findings.list_by_asset(affected_asset)
            if affected_asset is not None
            else self._findings.list_all()
        )

        knowledge_titles: dict[int, str] | None = None
        if self._knowledge is not None:
            knowledge_ids = {f.knowledge_source_id for f in findings if f.knowledge_source_id is not None}
            knowledge_titles = {}
            for knowledge_id in knowledge_ids:
                item = self._knowledge.get(knowledge_id)
                if item is not None:
                    knowledge_titles[knowledge_id] = item.title

        return self._report_generator.generate(
            findings=findings, output_path=output_path, knowledge_titles=knowledge_titles
        )
