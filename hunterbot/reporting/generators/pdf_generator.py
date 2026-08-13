from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from hunterbot.core.domain import Finding
from hunterbot.reporting.knowledge_labels import knowledge_source_label
from hunterbot.reporting.ordering import sort_findings

_TITLE_SIZE = 16
_HEADING_SIZE = 13
_LABEL_SIZE = 10
_BODY_SIZE = 10
_LINE_HEIGHT = 6


def _pdf_safe(text: str) -> str:
    """Coerce text into fpdf2's core-font (latin-1) charset.

    fpdf2's built-in Helvetica font only supports latin-1; anything outside
    that range (e.g. text pulled from arbitrary PDFs/HTML during ingestion)
    would otherwise raise. Unrepresentable characters are replaced rather
    than embedding a Unicode TTF font, keeping this generator dependency-free.
    """
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _paragraph(pdf: FPDF, height: float, text: str) -> None:
    """multi_cell that always leaves the cursor back at the left margin.

    fpdf2's multi_cell defaults to leaving the cursor at the end of the last
    line (new_x=RIGHT), which starves the *next* multi_cell of horizontal
    space unless every call explicitly resets it — so this wrapper does
    that once, for every paragraph-like write in this generator.
    """
    pdf.multi_cell(0, height, _pdf_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _write_labeled_line(pdf: FPDF, label: str, value: str) -> None:
    pdf.set_font("Helvetica", style="B", size=_LABEL_SIZE)
    pdf.write(_LINE_HEIGHT, _pdf_safe(f"{label}: "))
    pdf.set_font("Helvetica", size=_LABEL_SIZE)
    pdf.write(_LINE_HEIGHT, _pdf_safe(value))
    pdf.ln(_LINE_HEIGHT)


def _write_section(pdf: FPDF, label: str, value: str) -> None:
    pdf.set_font("Helvetica", style="B", size=_LABEL_SIZE)
    _paragraph(pdf, _LINE_HEIGHT, label)
    pdf.set_font("Helvetica", size=_BODY_SIZE)
    _paragraph(pdf, _LINE_HEIGHT, value)
    pdf.ln(2)


def _write_finding(pdf: FPDF, finding: Finding, knowledge_titles: dict[int, str] | None) -> None:
    pdf.set_font("Helvetica", style="B", size=_HEADING_SIZE)
    _paragraph(pdf, _LINE_HEIGHT + 1, f"[{finding.severity.value.upper()}] {finding.title}")
    pdf.ln(1)

    _write_labeled_line(pdf, "Category", finding.category.value)
    _write_labeled_line(pdf, "Confidence", finding.confidence.value)
    _write_labeled_line(pdf, "Affected asset", finding.affected_asset)
    _write_labeled_line(pdf, "Location", finding.location)
    _write_labeled_line(pdf, "Scanner", finding.scanner_name)
    _write_labeled_line(pdf, "Detected", finding.created_at.isoformat())
    label = knowledge_source_label(finding, knowledge_titles)
    if label is not None:
        _write_labeled_line(pdf, "Knowledge source", label)
    pdf.ln(2)

    _write_section(pdf, "Description", finding.description)
    for label, value in (
        ("Evidence", finding.evidence),
        ("Reproduction", finding.reproduction_steps),
        ("Impact", finding.impact),
        ("Remediation", finding.remediation),
    ):
        if value:
            _write_section(pdf, label, value)
    if finding.references:
        _write_section(pdf, "References", "\n".join(f"- {reference}" for reference in finding.references))

    pdf.ln(4)
    pdf.set_draw_color(200, 200, 200)
    y = pdf.get_y()
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(4)


class PDFReportGenerator:
    format_name = "pdf"

    def generate(
        self,
        *,
        findings: list[Finding],
        output_path: Path,
        knowledge_titles: dict[int, str] | None = None,
    ) -> Path:
        ordered = sort_findings(findings)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", style="B", size=_TITLE_SIZE)
        _paragraph(pdf, 10, "HunterBot Vulnerability Report")
        pdf.set_font("Helvetica", size=_BODY_SIZE)
        generated_at = datetime.now(timezone.utc).isoformat()
        _paragraph(pdf, _LINE_HEIGHT, f"Generated: {generated_at}    Total findings: {len(ordered)}")
        pdf.ln(4)

        if not ordered:
            _paragraph(pdf, _LINE_HEIGHT, "No findings.")
        for finding in ordered:
            _write_finding(pdf, finding, knowledge_titles)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(output_path))
        return output_path
