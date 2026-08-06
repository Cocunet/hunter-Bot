from hunterbot.authorization.exceptions import NotAuthorizedError
from hunterbot.core.domain import Scope
from hunterbot.core.interfaces import ScopeRepository


class ScopeAuthorizationService:
    """The single gate scan use-cases must pass through before touching a target.

    Deny-by-default: absence of a matching, active Scope means "not
    authorized", never "assume yes". This class contains no bypass or
    override path by design — see constraint #12 in the project brief.
    """

    def __init__(self, scope_repository: ScopeRepository) -> None:
        self._scopes = scope_repository

    def authorize(self, target: str) -> Scope:
        candidates = self._scopes.find_matching(target)
        active = [scope for scope in candidates if scope.is_currently_active()]
        if not active:
            raise NotAuthorizedError(target)
        # Prefer the most recently authorized active scope when several match.
        return max(active, key=lambda scope: scope.authorized_at)

    def is_authorized(self, target: str) -> bool:
        try:
            self.authorize(target)
        except NotAuthorizedError:
            return False
        return True
