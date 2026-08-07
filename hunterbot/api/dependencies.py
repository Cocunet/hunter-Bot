import secrets
from collections.abc import Iterator
from functools import lru_cache

from fastapi import Header, HTTPException, status
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from hunterbot.config import get_config
from hunterbot.storage.database import create_engine_from_url, get_session_factory, init_db


@lru_cache
def _engine() -> Engine:
    """Process-wide engine, created once and reused across requests.

    Unlike the CLI (a fresh process per invocation, so per-command setup
    cost doesn't matter), the API is a long-lived server — recreating an
    engine per request would open a new connection pool every time.
    """
    config = get_config()
    engine = create_engine_from_url(config.database_url)
    init_db(engine)
    return engine


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one Session per request, closed when it ends."""
    session_factory = get_session_factory(_engine())
    with session_factory() as session:
        yield session


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency, applied to every route: gate on HUNTERBOT_API_KEY.

    When unset (the default), this is a no-op — the API stays open, matching
    prior behavior for local/development use. When set, every request must
    carry it as ``Authorization: Bearer <api_key>``; comparison is constant-
    time (``secrets.compare_digest``) to avoid a timing side-channel on the
    key itself. This is deliberately the *only* access-control layer here —
    it says "this caller may use the API at all," not "for this specific
    Scope" — the existing ScopeAuthorizationService still separately governs
    which targets a scan may actually touch.
    """
    api_key = get_config().api_key
    if api_key is None:
        return

    expected = f"Bearer {api_key}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
