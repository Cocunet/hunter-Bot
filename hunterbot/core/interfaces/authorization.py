from typing import Protocol

from hunterbot.core.domain import Scope


class AuthorizationChecker(Protocol):
    """Gate that every scan use-case must pass through before touching a target.

    Deny-by-default: a target with no matching, active Scope is not authorized.
    """

    def authorize(self, target: str) -> Scope:
        """Return the matching active Scope, or raise NotAuthorizedError."""
        ...

    def is_authorized(self, target: str) -> bool: ...
