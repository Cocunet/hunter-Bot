import markdown
from bs4 import BeautifulSoup

_BLOCK_TAGS = ("p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "td", "th")
_NOISE_TAGS = ("script", "style", "nav", "header", "footer", "noscript", "svg")


def html_to_text(html: str) -> str:
    """Strip an HTML document down to its readable text, chunked by block element.

    Each block-level element (paragraph, list item, heading, ...) becomes one
    blank-line-separated chunk in the output, which is what downstream
    knowledge extraction splits on. Navigation/boilerplate tags are dropped
    entirely rather than converted to text.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(_NOISE_TAGS):
        tag.decompose()

    blocks = []
    for element in soup.find_all(_BLOCK_TAGS):
        block_text = " ".join(element.get_text().split())
        if block_text:
            blocks.append(block_text)

    if not blocks:
        # No recognized block tags (e.g. a bare text fragment) — fall back
        # to the whole document's text as a single chunk.
        whole_text = " ".join(soup.get_text().split())
        return whole_text

    return "\n\n".join(blocks)


def markdown_to_text(markdown_text: str) -> str:
    """Render Markdown to HTML, then reuse the HTML text-extraction path."""
    html = markdown.markdown(markdown_text)
    return html_to_text(html)


def plain_text_to_paragraphs(text: str) -> str:
    """Collapse a plain-text document (e.g. PDF-extracted text) into
    blank-line-separated paragraphs, trimming excess internal whitespace.
    """
    paragraphs: list[str] = []
    current_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line:
            current_lines.append(line)
        elif current_lines:
            paragraphs.append(" ".join(current_lines))
            current_lines = []
    if current_lines:
        paragraphs.append(" ".join(current_lines))
    return "\n\n".join(paragraphs)


def normalize(content: str, *, content_type: str) -> str:
    """Dispatch to the right normalizer for a RawDocument's content_type."""
    if content_type == "markdown":
        return markdown_to_text(content)
    if content_type == "html":
        return html_to_text(content)
    if content_type in ("pdf", "text"):
        return plain_text_to_paragraphs(content)
    raise ValueError(f"unsupported content type for normalization: {content_type!r}")
