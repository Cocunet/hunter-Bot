from datetime import datetime

from pydantic import BaseModel, Field

from hunterbot.core.domain import KnowledgeItem, KnowledgeItemRevision, Scope, SourceType


class ScopeCreateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    program_name: str = Field(min_length=1, max_length=255)
    authorized_by: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=2048)
    expires_at: datetime | None = None


class ScopeCheckResponse(BaseModel):
    authorized: bool
    scope: Scope | None = None


class SourceCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: SourceType
    url: str | None = Field(default=None, max_length=2048)
    license_note: str | None = Field(default=None, max_length=1024)


class IngestResponse(BaseModel):
    source_id: int
    items_extracted: int
    items_added: int
    items_updated: int
    items_unchanged: int


class SemanticMatchResponse(BaseModel):
    item: KnowledgeItem
    score: float


class SemanticSearchResponse(BaseModel):
    results: list[SemanticMatchResponse]
    used_semantic_backend: bool


class KnowledgeHistoryResponse(BaseModel):
    current: KnowledgeItem
    revisions: list[KnowledgeItemRevision]


class ScanRequest(BaseModel):
    base_url: str = Field(min_length=1, description="Full base URL to scan, e.g. https://example.com")
    adaptive: bool = Field(
        default=False,
        description=(
            "Use Claude to pick which registered scanners are worth running, based on a "
            "quick recon request, instead of always running all of them (requires the 'llm' extra)."
        ),
    )


class ReportRequest(BaseModel):
    format: str = Field(default="markdown", description="markdown, json, html, pdf, docx, or xlsx.")
    asset: str | None = Field(default=None, description="Limit the report to one affected_asset value.")


class AnalyzeRequest(BaseModel):
    asset: str | None = Field(default=None, description="Limit analysis to one affected_asset value.")
