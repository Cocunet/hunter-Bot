from __future__ import annotations

from typing import Protocol

from hunterbot.core.domain import AuthSession, Finding, KnowledgeItem, KnowledgeItemRevision, Scope, Source


class SourceRepository(Protocol):
    """Persistence contract for registered educational Sources."""

    def add(self, source: Source) -> Source:
        """Persist a new source and return it with its assigned id."""
        ...

    def update(self, source: Source) -> Source:
        """Persist changes to an already-registered source (must have an id)."""
        ...

    def get(self, source_id: int) -> Source | None: ...

    def list(self, *, enabled_only: bool = False) -> list[Source]: ...

    def get_by_name(self, name: str) -> Source | None: ...


class KnowledgeRepository(Protocol):
    """Persistence contract for structured KnowledgeItems."""

    def add(self, item: KnowledgeItem) -> KnowledgeItem:
        """Persist a new knowledge item and return it with its assigned id."""
        ...

    def update(self, item: KnowledgeItem) -> KnowledgeItem:
        """Overwrite an already-registered item's fields (must have an id).

        The caller (hunterbot.learning) is responsible for archiving the
        superseded values as a KnowledgeItemRevision first — this method
        does not do that itself.
        """
        ...

    def get(self, item_id: int) -> KnowledgeItem | None: ...

    def get_by_content_hash(self, content_hash: str) -> KnowledgeItem | None:
        """Look up an existing item by exact content hash, for dedupe checks."""
        ...

    def find_by_source_and_title(self, source_id: int, title: str) -> KnowledgeItem | None:
        """Look up the current item that shares identity with a candidate.

        Used by the learning engine to detect "this is an updated version of
        something we already know" versus "this is brand new knowledge",
        since content_hash alone changes whenever the text changes.
        """
        ...

    def list_by_source(self, source_id: int) -> list[KnowledgeItem]: ...

    def search(
        self,
        *,
        keyword: str | None = None,
        category: str | None = None,
        cwe: str | None = None,
        owasp_category: str | None = None,
        severity: str | None = None,
        tag: str | None = None,
    ) -> list[KnowledgeItem]: ...


class ScopeRepository(Protocol):
    """Persistence contract for authorized scan Scopes."""

    def add(self, scope: Scope) -> Scope:
        """Persist a new scope and return it with its assigned id."""
        ...

    def get(self, scope_id: int) -> Scope | None: ...

    def list(self) -> list[Scope]: ...

    def find_matching(self, target: str) -> list[Scope]:
        """Return all scopes whose ``target`` could authorize the given value."""
        ...


class AuthSessionRepository(Protocol):
    """Persistence contract for registered AuthSessions."""

    def add(self, session: AuthSession) -> AuthSession:
        """Persist a new auth session and return it with its assigned id."""
        ...

    def get(self, session_id: int) -> AuthSession | None: ...

    def list(self, *, scope_id: int | None = None) -> list[AuthSession]: ...


class FindingRepository(Protocol):
    """Persistence contract for scanner-produced Findings."""

    def add(self, finding: Finding) -> Finding:
        """Persist a new finding and return it with its assigned id."""
        ...

    def get(self, finding_id: int) -> Finding | None: ...

    def list_by_asset(self, affected_asset: str) -> list[Finding]: ...

    def list_all(self) -> list[Finding]: ...


class KnowledgeRevisionRepository(Protocol):
    """Persistence contract for archived KnowledgeItem revisions."""

    def add(self, revision: KnowledgeItemRevision) -> KnowledgeItemRevision:
        """Persist a superseded revision and return it with its assigned id."""
        ...

    def list_by_knowledge_item(self, knowledge_item_id: int) -> list[KnowledgeItemRevision]:
        """Oldest first: the full history of a KnowledgeItem's prior versions."""
        ...
