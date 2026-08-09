from datetime import datetime

from hunterbot.core.domain import AuthSession
from hunterbot.core.interfaces import AuthSessionRepository, ScopeRepository


class RegisterAuthSessionUseCase:
    """Registers externally-obtained authentication material for a Scope.

    Requires the target Scope to already exist -- a session is meaningless
    (and unusable, see RunScanUseCase's callers) without one to tie it to.
    """

    def __init__(self, *, auth_session_repository: AuthSessionRepository, scope_repository: ScopeRepository) -> None:
        self._sessions = auth_session_repository
        self._scopes = scope_repository

    def execute(
        self,
        *,
        scope_id: int,
        name: str,
        headers: dict[str, str],
        notes: str | None = None,
        expires_at: datetime | None = None,
    ) -> AuthSession:
        if self._scopes.get(scope_id) is None:
            raise ValueError(f"no scope with id {scope_id}")
        session = AuthSession(
            scope_id=scope_id,
            name=name,
            headers=headers,
            notes=notes,
            expires_at=expires_at,
        )
        return self._sessions.add(session)


class ListAuthSessionsUseCase:
    def __init__(self, auth_session_repository: AuthSessionRepository) -> None:
        self._sessions = auth_session_repository

    def execute(self, *, scope_id: int | None = None) -> list[AuthSession]:
        return self._sessions.list(scope_id=scope_id)
