from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, model_validator

from hunterbot.core.domain.enums import ScopeStatus


class Scope(BaseModel):
    """An explicitly authorized scan target.

    This is the sole record type the authorization gate (hunterbot.authorization)
    consults before any scan use-case is allowed to run. A target with no
    matching, active Scope is refused by default. ``target`` holds a hostname,
    domain (matched by suffix), or IPv4/IPv6 address/CIDR range.
    """

    model_config = ConfigDict(frozen=True)

    id: int | None = None
    target: str = Field(min_length=1, max_length=255)
    program_name: str = Field(min_length=1, max_length=255)
    authorized_by: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=2048)
    status: ScopeStatus = ScopeStatus.ACTIVE
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _check_expiry_after_authorization(self) -> "Scope":
        if self.expires_at is not None and self.expires_at <= self.authorized_at:
            raise ValueError("expires_at must be after authorized_at")
        return self

    def is_currently_active(self, *, now: datetime | None = None) -> bool:
        """Whether this scope grants authorization right now.

        Does not mutate ``status`` — an expired-but-still-ACTIVE record is
        treated as inactive here; a separate maintenance task transitions
        ``status`` to EXPIRED in storage.
        """
        if self.status != ScopeStatus.ACTIVE:
            return False
        if self.expires_at is None:
            return True
        current_time = now or datetime.now(timezone.utc)
        return current_time < self.expires_at
