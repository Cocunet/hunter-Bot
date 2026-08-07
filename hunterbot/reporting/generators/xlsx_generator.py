from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.worksheet.worksheet import Worksheet

from hunterbot.core.domain import Finding
from hunterbot.reporting.knowledge_labels import knowledge_source_label
from hunterbot.reporting.ordering import sort_findings

_HEADERS = (
    "ID",
    "Severity",
    "Title",
    "Category",
    "Confidence",
    "Affected Asset",
    "Location",
    "Scanner",
    "Detected",
    "Description",
    "Evidence",
    "Reproduction",
    "Impact",
    "Remediation",
    "References",
    "Knowledge Source",
)

_COLUMN_WIDTHS = (6, 10, 30, 24, 12, 24, 30, 20, 22, 40, 30, 30, 30, 30, 30, 30)


def _finding_row(finding: Finding, knowledge_titles: dict[int, str] | None) -> tuple:
    return (
        finding.id,
        finding.severity.value,
        finding.title,
        finding.category.value,
        finding.confidence.value,
        finding.affected_asset,
        finding.location,
        finding.scanner_name,
        finding.created_at.isoformat(),
        finding.description,
        finding.evidence or "",
        finding.reproduction_steps or "",
        finding.impact or "",
        finding.remediation or "",
        "; ".join(finding.references),
        knowledge_source_label(finding, knowledge_titles) or "",
    )


def _style_sheet(sheet: Worksheet) -> None:
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    sheet.freeze_panes = "A2"
    for index, width in enumerate(_COLUMN_WIDTHS, start=1):
        sheet.column_dimensions[sheet.cell(row=1, column=index).column_letter].width = width


class XLSXReportGenerator:
    format_name = "xlsx"

    def generate(
        self,
        *,
        findings: list[Finding],
        output_path: Path,
        knowledge_titles: dict[int, str] | None = None,
    ) -> Path:
        ordered = sort_findings(findings)

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Findings"
        sheet.append(_HEADERS)
        for finding in ordered:
            sheet.append(_finding_row(finding, knowledge_titles))
        _style_sheet(sheet)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(str(output_path))
        return output_path
