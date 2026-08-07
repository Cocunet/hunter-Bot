from pathlib import Path
from typing import Protocol

from hunterbot.core.domain import Finding


class ReportGenerator(Protocol):
    """Serializes a set of Findings into one report file format.

    Adding a new output format (PDF, DOCX, XLSX, ...) means writing a class
    that satisfies this Protocol — nothing in hunterbot.core or the calling
    use-case needs to change.
    """

    format_name: str

    def generate(self, *, findings: list[Finding], output_path: Path) -> Path: ...
