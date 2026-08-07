from pathlib import Path
from typing import Protocol

from hunterbot.core.domain import Finding


class ReportGenerator(Protocol):
    """Serializes a set of Findings into one report file format.

    Adding a new output format (PDF, DOCX, XLSX, ...) means writing a class
    that satisfies this Protocol — nothing in hunterbot.core or the calling
    use-case needs to change.

    Generators do no I/O of their own beyond writing ``output_path`` — they
    never look up a KnowledgeItem by id themselves. ``knowledge_titles`` is
    a fully-resolved {id: title} map the caller (GenerateReportUseCase)
    builds ahead of time, so a Finding's ``knowledge_source_id`` can be
    rendered as a readable title instead of a bare number.
    """

    format_name: str

    def generate(
        self,
        *,
        findings: list[Finding],
        output_path: Path,
        knowledge_titles: dict[int, str] | None = None,
    ) -> Path: ...
