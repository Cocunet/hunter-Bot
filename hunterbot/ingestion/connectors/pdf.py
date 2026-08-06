from pathlib import Path

from pypdf import PdfReader

from hunterbot.ingestion.connectors.base import RawDocument


class PDFFileConnector:
    """Extracts text from a local PDF document, page by page."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def fetch(self) -> RawDocument:
        reader = PdfReader(str(self._path))
        pages = [page.extract_text() or "" for page in reader.pages]
        content = "\n\n".join(pages)
        return RawDocument(content=content, content_type="pdf", origin=str(self._path))
