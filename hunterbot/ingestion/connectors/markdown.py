from pathlib import Path

from hunterbot.ingestion.connectors.base import RawDocument


class MarkdownFileConnector:
    """Reads a local Markdown file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def fetch(self) -> RawDocument:
        content = self._path.read_text(encoding="utf-8")
        return RawDocument(content=content, content_type="markdown", origin=str(self._path))
