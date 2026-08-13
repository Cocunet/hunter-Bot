from pathlib import Path

from hunterbot.ingestion.connectors.base import RawDocument


class HTMLFileConnector:
    """Reads a local HTML file.

    Fetching HTML pages over the network (e.g. via requests/Playwright for
    JS-rendered content) is a connector to add in a later ingestion slice;
    this one covers already-retrieved/local HTML for now.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def fetch(self) -> RawDocument:
        content = self._path.read_text(encoding="utf-8")
        return RawDocument(content=content, content_type="html", origin=str(self._path))
