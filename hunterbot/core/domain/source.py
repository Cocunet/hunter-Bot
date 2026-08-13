from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from hunterbot.core.domain.enums import SourceType


class Source(BaseModel):
    """A registered educational resource that knowledge is ingested from.

    Every KnowledgeItem traces back to exactly one Source, which is how the
    knowledge base preserves provenance (constraint: "track the source of
    every extracted piece of information").
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    name: str = Field(min_length=1, max_length=255)
    source_type: SourceType
    url: str | None = Field(default=None, max_length=2048)
    license_note: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_fetched_at: datetime | None = None
