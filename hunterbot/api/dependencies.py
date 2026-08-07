from collections.abc import Iterator
from functools import lru_cache

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
