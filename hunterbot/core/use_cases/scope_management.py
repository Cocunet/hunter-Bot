from datetime import datetime

from hunterbot.core.domain import Scope
from hunterbot.core.interfaces import ScopeRepository


class RegisterScopeUseCase:
    """Registers a new authorized scan target.

    This is the only supported way to grant authorization for a target —
    there is deliberately no use-case that scans without a corresponding
    Scope record.
    """

    def __init__(self, scope_repository: ScopeRepository) -> None:
        self._scopes = scope_repository

    def execute(
        self,
        *,
        target: str,
        program_name: str,
        authorized_by: str,
        notes: str | None = None,
        expires_at: datetime | None = None,
    ) -> Scope:
        scope = Scope(
            target=target,
            program_name=program_name,
            authorized_by=authorized_by,
            notes=notes,
            expires_at=expires_at,
        )
        return self._scopes.add(scope)


class ListScopesUseCase:
    def __init__(self, scope_repository: ScopeRepository) -> None:
        self._scopes = scope_repository

    def execute(self) -> list[Scope]:
        return self._scopes.list()
