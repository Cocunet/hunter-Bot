from hunterbot.ingestion.connectors.base import Connector, RawDocument
from hunterbot.ingestion.connectors.html import HTMLFileConnector
from hunterbot.ingestion.connectors.markdown import MarkdownFileConnector
from hunterbot.ingestion.connectors.pdf import PDFFileConnector
from hunterbot.ingestion.connectors.registry import connector_for_path

__all__ = [
    "Connector",
    "HTMLFileConnector",
    "MarkdownFileConnector",
    "PDFFileConnector",
    "RawDocument",
    "connector_for_path",
]
