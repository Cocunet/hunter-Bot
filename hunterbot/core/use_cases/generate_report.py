from pathlib import Path

from hunterbot.core.interfaces import FindingRepository, ReportGenerator


class GenerateReportUseCase:
    """Pulls Findings from storage and hands them to a ReportGenerator.

    Depends only on the FindingRepository and ReportGenerator Protocols —
    which concrete storage backend and output format are used is decided by
    the caller (composition root), not this use-case.
    """

    def __init__(self, *, finding_repository: FindingRepository, report_generator: ReportGenerator) -> None:
        self._findings = finding_repository
        self._report_generator = report_generator

    def execute(self, *, output_path: Path, affected_asset: str | None = None) -> Path:
        findings = (
            self._findings.list_by_asset(affected_asset)
            if affected_asset is not None
            else self._findings.list_all()
        )
        return self._report_generator.generate(findings=findings, output_path=output_path)
