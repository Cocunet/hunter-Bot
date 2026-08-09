from sqlalchemy.orm import Session

from hunterbot.core.domain import AuthSession, Scope, Source, SourceType
from hunterbot.storage.repositories import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyScopeRepository,
    SqlAlchemySourceRepository,
)


class TestSqlAlchemySourceRepository:
    def test_add_assigns_id_and_round_trips_fields(self, session: Session) -> None:
        repo = SqlAlchemySourceRepository(session)
        source = Source(name="OWASP Top 10", source_type=SourceType.DOCUMENTATION, url="https://owasp.org")

        saved = repo.add(source)

        assert saved.id is not None
        assert saved.name == "OWASP Top 10"
        assert saved.source_type == SourceType.DOCUMENTATION

    def test_get_by_name_finds_existing(self, session: Session) -> None:
        repo = SqlAlchemySourceRepository(session)
        repo.add(Source(name="PortSwigger Academy", source_type=SourceType.WRITEUP))

        found = repo.get_by_name("PortSwigger Academy")

        assert found is not None
        assert found.name == "PortSwigger Academy"

    def test_get_by_name_returns_none_when_missing(self, session: Session) -> None:
        repo = SqlAlchemySourceRepository(session)
        assert repo.get_by_name("nonexistent") is None

    def test_list_enabled_only_filters_disabled_sources(self, session: Session) -> None:
        repo = SqlAlchemySourceRepository(session)
        repo.add(Source(name="Active Source", source_type=SourceType.BLOG, enabled=True))
        repo.add(Source(name="Disabled Source", source_type=SourceType.BLOG, enabled=False))

        enabled = repo.list(enabled_only=True)

        assert [s.name for s in enabled] == ["Active Source"]


class TestSqlAlchemyScopeRepository:
    def test_find_matching_returns_subdomain_matches(self, session: Session) -> None:
        repo = SqlAlchemyScopeRepository(session)
        repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))

        matches = repo.find_matching("api.example.com")

        assert len(matches) == 1
        assert matches[0].target == "example.com"

    def test_find_matching_excludes_unrelated_targets(self, session: Session) -> None:
        repo = SqlAlchemyScopeRepository(session)
        repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))

        assert repo.find_matching("other.com") == []


class TestSqlAlchemyAuthSessionRepository:
    def test_add_assigns_id_and_round_trips_headers(self, session: Session) -> None:
        scope = SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        repo = SqlAlchemyAuthSessionRepository(session)
        auth_session = AuthSession(
            scope_id=scope.id, name="admin-user", headers={"Cookie": "session=abc123"}
        )

        saved = repo.add(auth_session)

        assert saved.id is not None
        assert saved.scope_id == scope.id
        assert saved.headers == {"Cookie": "session=abc123"}

    def test_get_returns_none_when_missing(self, session: Session) -> None:
        repo = SqlAlchemyAuthSessionRepository(session)
        assert repo.get(999) is None

    def test_list_filters_by_scope_id(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_a = scope_repo.add(Scope(target="a.example.com", program_name="Acme", authorized_by="Alice"))
        scope_b = scope_repo.add(Scope(target="b.example.com", program_name="Acme", authorized_by="Alice"))
        repo = SqlAlchemyAuthSessionRepository(session)
        repo.add(AuthSession(scope_id=scope_a.id, name="session-a", headers={"Cookie": "a"}))
        repo.add(AuthSession(scope_id=scope_b.id, name="session-b", headers={"Cookie": "b"}))

        results = repo.list(scope_id=scope_a.id)

        assert [s.name for s in results] == ["session-a"]

    def test_list_without_filter_returns_all(self, session: Session) -> None:
        scope = SqlAlchemyScopeRepository(session).add(
            Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        )
        repo = SqlAlchemyAuthSessionRepository(session)
        repo.add(AuthSession(scope_id=scope.id, name="session-a", headers={"Cookie": "a"}))
        repo.add(AuthSession(scope_id=scope.id, name="session-b", headers={"Cookie": "b"}))

        assert len(repo.list()) == 2
