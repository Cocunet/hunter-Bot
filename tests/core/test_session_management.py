import pytest
from sqlalchemy.orm import Session

from hunterbot.core.domain import Scope
from hunterbot.core.use_cases.session_management import ListAuthSessionsUseCase, RegisterAuthSessionUseCase
from hunterbot.storage.repositories import SqlAlchemyAuthSessionRepository, SqlAlchemyScopeRepository


class TestRegisterAuthSessionUseCase:
    def test_registers_session_for_existing_scope(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope = scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        use_case = RegisterAuthSessionUseCase(
            auth_session_repository=SqlAlchemyAuthSessionRepository(session), scope_repository=scope_repo
        )

        auth_session = use_case.execute(scope_id=scope.id, name="admin-user", headers={"Cookie": "session=abc"})

        assert auth_session.id is not None
        assert auth_session.scope_id == scope.id
        assert auth_session.headers == {"Cookie": "session=abc"}

    def test_rejects_nonexistent_scope(self, session: Session) -> None:
        use_case = RegisterAuthSessionUseCase(
            auth_session_repository=SqlAlchemyAuthSessionRepository(session),
            scope_repository=SqlAlchemyScopeRepository(session),
        )

        with pytest.raises(ValueError, match="no scope with id"):
            use_case.execute(scope_id=999, name="admin-user", headers={"Cookie": "session=abc"})


class TestListAuthSessionsUseCase:
    def test_lists_sessions_for_scope(self, session: Session) -> None:
        scope_repo = SqlAlchemyScopeRepository(session)
        scope = scope_repo.add(Scope(target="example.com", program_name="Acme", authorized_by="Alice"))
        session_repo = SqlAlchemyAuthSessionRepository(session)
        RegisterAuthSessionUseCase(auth_session_repository=session_repo, scope_repository=scope_repo).execute(
            scope_id=scope.id, name="admin-user", headers={"Cookie": "session=abc"}
        )

        results = ListAuthSessionsUseCase(session_repo).execute(scope_id=scope.id)

        assert len(results) == 1
        assert results[0].name == "admin-user"

    def test_empty_when_none_registered(self, session: Session) -> None:
        results = ListAuthSessionsUseCase(SqlAlchemyAuthSessionRepository(session)).execute()
        assert results == []
