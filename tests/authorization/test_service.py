from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from hunterbot.authorization import NotAuthorizedError, ScopeAuthorizationService
from hunterbot.core.domain import Scope, ScopeStatus
from hunterbot.storage.repositories import SqlAlchemyScopeRepository


def _service(session: Session) -> ScopeAuthorizationService:
    return ScopeAuthorizationService(SqlAlchemyScopeRepository(session))


class TestScopeAuthorizationService:
    def test_target_with_no_scope_is_not_authorized(self, session: Session) -> None:
        service = _service(session)
        assert service.is_authorized("example.com") is False

    def test_target_with_no_scope_raises_on_authorize(self, session: Session) -> None:
        service = _service(session)
        with pytest.raises(NotAuthorizedError):
            service.authorize("example.com")

    def test_target_with_active_scope_is_authorized(self, session: Session) -> None:
        repo = SqlAlchemyScopeRepository(session)
        repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))

        service = _service(session)

        assert service.is_authorized("example.com") is True
        assert service.authorize("app.example.com").program_name == "Acme"

    def test_revoked_scope_does_not_authorize(self, session: Session) -> None:
        repo = SqlAlchemyScopeRepository(session)
        repo.add(
            Scope(
                target="example.com",
                program_name="Acme",
                authorized_by="Alice",
                status=ScopeStatus.REVOKED,
            )
        )

        service = _service(session)

        assert service.is_authorized("example.com") is False

    def test_expired_scope_does_not_authorize(self, session: Session) -> None:
        repo = SqlAlchemyScopeRepository(session)
        now = datetime.now(timezone.utc)
        repo.add(
            Scope(
                target="example.com",
                program_name="Acme",
                authorized_by="Alice",
                authorized_at=now - timedelta(days=10),
                expires_at=now - timedelta(days=1),
            )
        )

        service = _service(session)

        assert service.is_authorized("example.com") is False

    def test_picks_most_recently_authorized_active_scope_when_multiple_match(
        self, session: Session
    ) -> None:
        repo = SqlAlchemyScopeRepository(session)
        now = datetime.now(timezone.utc)
        repo.add(
            Scope(
                target="example.com",
                program_name="Old Program",
                authorized_by="Alice",
                authorized_at=now - timedelta(days=5),
            )
        )
        repo.add(
            Scope(
                target="example.com",
                program_name="New Program",
                authorized_by="Bob",
                authorized_at=now,
            )
        )

        service = _service(session)

        assert service.authorize("example.com").program_name == "New Program"
