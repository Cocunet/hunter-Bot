from hunterbot.reporting.generators.html_generator import HTMLReportGenerator
from hunterbot.reporting.generators.json_generator import JSONReportGenerator
from hunterbot.reporting.generators.markdown_generator import MarkdownReportGenerator

_GENERATORS = {
    "markdown": MarkdownReportGenerator,
    "json": JSONReportGenerator,
    "html": HTMLReportGenerator,
}


def get_generator(format_name: str):
    """Look up a built-in ReportGenerator by format name.

    PDF/DOCX/XLSX generators land in a later slice and register here the
    same way — nothing else about this lookup changes when they do.
    """
    try:
        generator_cls = _GENERATORS[format_name]
    except KeyError:
        supported = ", ".join(sorted(_GENERATORS))
        raise ValueError(f"unsupported report format {format_name!r} (supported: {supported})") from None
    return generator_cls()


__all__ = ["HTMLReportGenerator", "JSONReportGenerator", "MarkdownReportGenerator", "get_generator"]
