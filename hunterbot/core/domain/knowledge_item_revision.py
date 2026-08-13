from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from hunterbot.core.domain.enums import Severity


class KnowledgeItemRevision(BaseModel):
    """An archived, superseded version of a KnowledgeItem.

    Written by the learning engine (hunterbot.learning) whenever re-ingestion
    finds updated content for a KnowledgeItem it already knows about — the
    old field values are captured here before the live row is overwritten,
    so history is never lost even though the KnowledgeItem itself is not
    append-only.
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    knowledge_item_id: int
    version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1)
    content_hash: str = Field(min_length=64, max_length=64)
    cwe: str | None = None
    owasp_category: str | None = None
    severity_hint: Severity | None = None
    tags: tuple[str, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    superseded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
