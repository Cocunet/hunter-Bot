from sqlalchemy.orm import Session

from hunterbot.core.domain import Scope, Source, SourceType
from hunterbot.storage.repositories import SqlAlchemyScopeRepository, SqlAlchemySourceRepository


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
