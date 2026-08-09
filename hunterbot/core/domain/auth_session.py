from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hunterbot.core.domain.timestamps import ensure_utc

_REDACTED = "***redacted***"


class AuthSession(BaseModel):
    """Externally-obtained authentication material to attach to scan requests.

    HunterBot never performs a login itself: login flows vary too much
    (CSRF tokens, MFA, OAuth redirects) to automate safely and generically,
    and doing so would mean issuing state-changing POST requests, breaking
    the read-only, GET-only boundary every scanner otherwise respects.
    Instead, an authorized tester logs in out-of-band (browser, curl,
    their own tooling) and registers the resulting session material here —
    a session cookie, a bearer token, whatever header(s) the target's auth
    scheme needs — so scans can reuse it. ``headers`` are attached verbatim
    to every request a scan makes once this session is selected; nothing
    here inspects or interprets them.

    Tied to a Scope by ``scope_id`` rather than to a raw target string, so
    a session can only ever be used for a target its owning Scope actually
    authorizes — see how RunScanUseCase's callers (CLI/API) enforce this
    before a scan starts.
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    scope_id: int
    name: str = Field(min_length=1, max_length=255)
    headers: dict[str, str] = Field(min_length=1)
    notes: str | None = Field(default=None, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    @field_validator("created_at", "expires_at", mode="before")
    @classmethod
    def _normalize_timezone(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value)

    def is_currently_active(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return True
        current_time = now or datetime.now(timezone.utc)
        return current_time < self.expires_at

    def masked_headers(self) -> dict[str, str]:
        """Header names with values redacted, for display in listings.

        The real values are credential material (session cookies, bearer
        tokens); nothing that only needs to show *which* headers a session
        configures — CLI/API listing output — should ever render them.
        """
        return dict.fromkeys(self.headers, _REDACTED)
