from pathlib import Path

import pytest

from hunterbot.ingestion.connectors import (
    HTMLFileConnector,
    MarkdownFileConnector,
    PDFFileConnector,
    connector_for_path,
)


class TestMarkdownFileConnector:
    def test_fetch_reads_file_content(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.md"
        path.write_text("# Heading\n\nBody text.", encoding="utf-8")

        document = MarkdownFileConnector(path).fetch()

        assert document.content == "# Heading\n\nBody text."
        assert document.content_type == "markdown"
        assert document.origin == str(path)


class TestHTMLFileConnector:
    def test_fetch_reads_file_content(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.html"
        path.write_text("<p>Hello</p>", encoding="utf-8")

        document = HTMLFileConnector(path).fetch()

        assert document.content == "<p>Hello</p>"
        assert document.content_type == "html"


class TestConnectorForPath:
    def test_selects_markdown_connector(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.md"
        path.write_text("content", encoding="utf-8")
        assert isinstance(connector_for_path(path), MarkdownFileConnector)

    def test_selects_html_connector(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.html"
        path.write_text("content", encoding="utf-8")
        assert isinstance(connector_for_path(path), HTMLFileConnector)

    def test_selects_pdf_connector(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.pdf"
        path.write_text("content", encoding="utf-8")
        assert isinstance(connector_for_path(path), PDFFileConnector)

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.docx"
        with pytest.raises(ValueError, match="no ingestion connector"):
            connector_for_path(path)
