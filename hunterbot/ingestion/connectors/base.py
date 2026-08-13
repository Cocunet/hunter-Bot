from datetime import datetime, timezone
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class RawDocument(BaseModel):
    """Unprocessed content fetched by a Connector, plus retrieval metadata.

    Internal to the ingestion pipeline — never persisted as-is. The
    normalization step turns ``content`` into clean text before it reaches
    knowledge extraction.
    """

    model_config = ConfigDict(frozen=True)

    content: str
    content_type: str
    origin: str = Field(min_length=1, max_length=2048)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Connector(Protocol):
    """Retrieves raw content for a single educational resource."""

    def fetch(self) -> RawDocument: ...
