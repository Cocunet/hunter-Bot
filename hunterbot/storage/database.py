from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models in hunterbot.storage."""


def create_engine_from_url(database_url: str) -> Engine:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args)


def init_db(engine: Engine) -> None:
    """Create all tables that don't exist yet.

    There is no schema history to manage at this stage of the project, so
    this uses ``metadata.create_all`` directly. Once the schema needs
    versioned migrations (e.g. after the knowledge/learning modules land),
    this should be replaced with Alembic.
    """
    from hunterbot.storage import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine)


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
