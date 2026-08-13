from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator):
    """A DateTime column that always round-trips as timezone-aware UTC.

    SQLite has no native timezone-aware storage: SQLAlchemy's
    ``DateTime(timezone=True)`` silently returns naive datetimes back from
    SQLite, which breaks comparisons against aware ``datetime.now(timezone.utc)``
    values elsewhere in the codebase (e.g. ``Scope.is_currently_active``).
    This type stores values as naive UTC and re-attaches UTC tzinfo on read,
    so callers never have to think about the underlying dialect.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("UTCDateTime requires timezone-aware datetimes")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)
