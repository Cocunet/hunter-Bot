from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from hunterbot.core.domain.enums import Confidence, Severity, VulnerabilityCategory


class Finding(BaseModel):
    """A single vulnerability finding produced by a scanner plugin.

    Fields mirror the reporting requirements directly (title, category,
    severity, confidence, evidence, remediation, ...) so report generators
    (hunterbot.reporting, added in a later slice) can serialize a Finding to
    any output format without additional mapping.
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    title: str = Field(min_length=1, max_length=255)
    category: VulnerabilityCategory
    severity: Severity
    confidence: Confidence
    description: str = Field(min_length=1)
    affected_asset: str = Field(min_length=1, max_length=255)
    location: str = Field(min_length=1, max_length=2048)
    evidence: str | None = None
    reproduction_steps: str | None = None
    impact: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = Field(default_factory=tuple)
    knowledge_source_id: int | None = None
    scanner_name: str = Field(min_length=1, max_length=255)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
