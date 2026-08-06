import pytest
from sqlalchemy.orm import Session

from hunterbot.storage.database import create_engine_from_url, get_session_factory, init_db


@pytest.fixture
def session() -> Session:
    engine = create_engine_from_url("sqlite:///:memory:")
    init_db(engine)
    session_factory = get_session_factory(engine)
    with session_factory() as db_session:
        yield db_session
