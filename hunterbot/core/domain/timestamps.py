from datetime import datetime, timezone


def ensure_utc(value: datetime | None) -> datetime | None:
    """Attach UTC tzinfo to a naive datetime; leave an already-aware one untouched.

    Any entry point that hands a datetime into the domain can produce a
    naive one -- a CLI option parsed from a date-only string, an API
    request body without a timezone suffix -- and both the domain's own
    comparisons (e.g. Scope.expires_at vs. authorized_at) and storage
    (UTCDateTime) require timezone-aware values. Used as a pydantic
    ``mode="before"`` validator on every datetime field a caller can
    supply, rather than trusted to each call site to remember.
    """
    if value is None or not isinstance(value, datetime):
        return value
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
