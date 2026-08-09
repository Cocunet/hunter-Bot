from datetime import datetime

from pydantic import BaseModel, Field

from hunterbot.core.domain import AuthSession, KnowledgeItem, KnowledgeItemRevision, Scope, SourceType


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


class AuthSessionCreateRequest(BaseModel):
    scope_id: int
    name: str = Field(min_length=1, max_length=255)
    headers: dict[str, str] = Field(
        min_length=1,
        description="HTTP headers attached to every scan request when this session is used, e.g. "
        '{"Cookie": "session=abc123"} or {"Authorization": "Bearer ..."}. Obtained by logging in '
        "out-of-band -- HunterBot never performs a login itself.",
    )
    notes: str | None = Field(default=None, max_length=1024)
    expires_at: datetime | None = None


class AuthSessionResponse(BaseModel):
    """Same shape as AuthSession, but with header values redacted.

    Header names are shown (so a caller can confirm what's configured);
    values are credential material and are never returned once stored.
    """

    id: int | None
    scope_id: int
    name: str
    headers: dict[str, str]
    notes: str | None
    created_at: datetime
    expires_at: datetime | None
    is_active: bool

    @classmethod
    def from_domain(cls, auth_session: AuthSession) -> "AuthSessionResponse":
        return cls(
            id=auth_session.id,
            scope_id=auth_session.scope_id,
            name=auth_session.name,
            headers=auth_session.masked_headers(),
            notes=auth_session.notes,
            created_at=auth_session.created_at,
            expires_at=auth_session.expires_at,
            is_active=auth_session.is_currently_active(),
        )


class ScanRequest(BaseModel):
    base_url: str = Field(min_length=1, description="Full base URL to scan, e.g. https://example.com")
    adaptive: bool = Field(
        default=False,
        description=(
            "Use Claude to pick which registered scanners are worth running, based on a "
            "quick recon request, instead of always running all of them (requires the 'llm' extra)."
        ),
    )
    session_id: int | None = Field(
        default=None,
        description="id of a registered auth session to authenticate scan requests with.",
    )


class AccessControlScanRequest(BaseModel):
    base_url: str = Field(min_length=1, description="Full base URL to scan, e.g. https://example.com")
    baseline_session_id: int = Field(
        description="id of the AuthSession that owns the resources referenced by candidate_paths."
    )
    test_session_id: int = Field(
        description="id of a second, independent AuthSession being tested for cross-account access."
    )
    candidate_paths: list[str] = Field(
        min_length=1,
        description="Resource-identifying paths to test, e.g. ['/api/orders/1001']. Both sessions' "
        "owning scopes must authorize base_url's hostname.",
    )


class ReportRequest(BaseModel):
    format: str = Field(default="markdown", description="markdown, json, html, pdf, docx, or xlsx.")
    asset: str | None = Field(default=None, description="Limit the report to one affected_asset value.")


class AnalyzeRequest(BaseModel):
    asset: str | None = Field(default=None, description="Limit analysis to one affected_asset value.")
