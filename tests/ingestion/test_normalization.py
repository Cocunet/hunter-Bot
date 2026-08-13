from hunterbot.ingestion.normalization.text_cleaner import (
    html_to_text,
    markdown_to_text,
    normalize,
    plain_text_to_paragraphs,
)


class TestHtmlToText:
    def test_extracts_paragraph_text(self) -> None:
        html = "<html><body><p>First paragraph.</p><p>Second paragraph.</p></body></html>"
        assert html_to_text(html) == "First paragraph.\n\nSecond paragraph."

    def test_drops_script_and_nav_content(self) -> None:
        html = (
            "<html><body>"
            "<nav>Home | About</nav>"
            "<script>trackUser();</script>"
            "<p>Real content here.</p>"
            "</body></html>"
        )
        result = html_to_text(html)
        assert "Home" not in result
        assert "trackUser" not in result
        assert "Real content here." in result

    def test_collapses_internal_whitespace(self) -> None:
        html = "<p>Too    many\n   spaces</p>"
        assert html_to_text(html) == "Too many spaces"


class TestMarkdownToText:
    def test_converts_heading_and_paragraph(self) -> None:
        markdown_text = "# Title\n\nSome body text."
        result = markdown_to_text(markdown_text)
        assert "Title" in result
        assert "Some body text." in result


class TestPlainTextToParagraphs:
    def test_splits_on_blank_lines(self) -> None:
        text = "Line one.\nLine one continued.\n\nLine two."
        result = plain_text_to_paragraphs(text)
        assert result == "Line one. Line one continued.\n\nLine two."

    def test_strips_trailing_whitespace_per_line(self) -> None:
        text = "  padded line  \n\nnext paragraph"
        assert plain_text_to_paragraphs(text) == "padded line\n\nnext paragraph"


class TestNormalizeDispatch:
    def test_unsupported_content_type_raises(self) -> None:
        try:
            normalize("data", content_type="video")
        except ValueError as exc:
            assert "video" in str(exc)
        else:
            raise AssertionError("expected ValueError for unsupported content type")
