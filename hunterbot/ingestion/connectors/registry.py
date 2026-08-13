from pathlib import Path

from hunterbot.ingestion.connectors.base import Connector
from hunterbot.ingestion.connectors.html import HTMLFileConnector
from hunterbot.ingestion.connectors.markdown import MarkdownFileConnector
from hunterbot.ingestion.connectors.pdf import PDFFileConnector

_EXTENSION_CONNECTORS: dict[str, type] = {
    ".md": MarkdownFileConnector,
    ".markdown": MarkdownFileConnector,
    ".html": HTMLFileConnector,
    ".htm": HTMLFileConnector,
    ".pdf": PDFFileConnector,
}


def connector_for_path(path: str | Path) -> Connector:
    """Pick the right file-based Connector for ``path`` by its extension."""
    suffix = Path(path).suffix.lower()
    connector_cls = _EXTENSION_CONNECTORS.get(suffix)
    if connector_cls is None:
        supported = ", ".join(sorted(_EXTENSION_CONNECTORS))
        raise ValueError(f"no ingestion connector for extension {suffix!r} (supported: {supported})")
    return connector_cls(path)
