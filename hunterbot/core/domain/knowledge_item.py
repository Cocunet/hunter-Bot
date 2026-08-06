from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from hunterbot.core.domain.enums import Severity, VulnerabilityCategory


class KnowledgeItem(BaseModel):
    """A single unit of structured knowledge extracted from a Source.

    ``content_hash`` is a stable hash of the normalized extracted text and is
    what the learning engine uses to detect duplicates before merging new
    knowledge into the base (see hunterbot.learning, added in a later slice).
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    source_id: int
    category: VulnerabilityCategory
    title: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1)
    content_hash: str = Field(min_length=64, max_length=64)
    cwe: str | None = Field(default=None, max_length=32)
    owasp_category: str | None = Field(default=None, max_length=64)
    severity_hint: Severity | None = None
    tags: tuple[str, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    version: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
