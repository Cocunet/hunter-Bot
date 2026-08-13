from hunterbot.reporting.generators.docx_generator import DOCXReportGenerator
from hunterbot.reporting.generators.html_generator import HTMLReportGenerator
from hunterbot.reporting.generators.json_generator import JSONReportGenerator
from hunterbot.reporting.generators.markdown_generator import MarkdownReportGenerator
from hunterbot.reporting.generators.pdf_generator import PDFReportGenerator
from hunterbot.reporting.generators.xlsx_generator import XLSXReportGenerator

_GENERATORS = {
    "markdown": MarkdownReportGenerator,
    "json": JSONReportGenerator,
    "html": HTMLReportGenerator,
    "pdf": PDFReportGenerator,
    "docx": DOCXReportGenerator,
    "xlsx": XLSXReportGenerator,
}


def get_generator(format_name: str):
    """Look up a built-in ReportGenerator by format name."""
    try:
        generator_cls = _GENERATORS[format_name]
    except KeyError:
        supported = ", ".join(sorted(_GENERATORS))
        raise ValueError(f"unsupported report format {format_name!r} (supported: {supported})") from None
    return generator_cls()


__all__ = [
    "DOCXReportGenerator",
    "HTMLReportGenerator",
    "JSONReportGenerator",
    "MarkdownReportGenerator",
    "PDFReportGenerator",
    "XLSXReportGenerator",
    "get_generator",
]
